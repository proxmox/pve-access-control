package PVE::API2::AccessControl;

use strict;
use warnings;

use JSON;
use MIME::Base64;

use PVE::Exception qw(raise raise_perm_exc raise_param_exc);
use PVE::SafeSyslog;
use PVE::RPCEnvironment;
use PVE::Cluster qw(cfs_read_file);
use PVE::DataCenterConfig;
use PVE::RESTHandler;
use PVE::AccessControl;
use PVE::JSONSchema qw(get_standard_option);
use PVE::API2::Domains;
use PVE::API2::User;
use PVE::API2::Group;
use PVE::API2::Role;
use PVE::API2::ACL;
use PVE::Auth::Plugin;
use PVE::OTP;
use PVE::Tools;

my $u2f_available = 0;
eval {
    require PVE::U2F;
    $u2f_available = 1;
};

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PVE::API2::User",  
    path => 'users',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Group",  
    path => 'groups',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Role",  
    path => 'roles',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::ACL",  
    path => 'acl',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Domains",  
    path => 'domains',
});

__PACKAGE__->register_method ({
    name => 'index', 
    path => '', 
    method => 'GET',
    description => "Directory index.",
    permissions => { 
	user => 'all',
    },
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;
    
	my $res = [];

	my $ma = __PACKAGE__->method_attributes();

	foreach my $info (@$ma) {
	    next if !$info->{subclass};

	    my $subpath = $info->{match_re}->[0];

	    push @$res, { subdir => $subpath };
	}

	push @$res, { subdir => 'ticket' };
	push @$res, { subdir => 'password' };

	return $res;
    }});


my $verify_auth = sub {
    my ($rpcenv, $username, $pw_or_ticket, $otp, $path, $privs) = @_;

    my $normpath = PVE::AccessControl::normalize_path($path);

    my $ticketuser;
    if (($ticketuser = PVE::AccessControl::verify_ticket($pw_or_ticket, 1)) &&
	($ticketuser eq $username)) {
	# valid ticket
    } elsif (PVE::AccessControl::verify_vnc_ticket($pw_or_ticket, $username, $normpath, 1)) {
	# valid vnc ticket
    } else {
	$username = PVE::AccessControl::authenticate_user($username, $pw_or_ticket, $otp);
    }

    my $privlist = [ PVE::Tools::split_list($privs) ];
    if (!($normpath && scalar(@$privlist) && $rpcenv->check($username, $normpath, $privlist))) {
	die "no permission ($path, $privs)\n";
    }

    return { username => $username };
};

my $create_ticket = sub {
    my ($rpcenv, $username, $pw_or_ticket, $otp) = @_;

    my ($ticketuser, undef, $tfa_info) = PVE::AccessControl::verify_ticket($pw_or_ticket, 1);
    if (defined($ticketuser) && ($ticketuser eq 'root@pam' || $ticketuser eq $username)) {
	if (defined($tfa_info)) {
	    die "incomplete ticket\n";
	}
	# valid ticket. Note: root@pam can create tickets for other users
    } else {
	($username, $tfa_info) = PVE::AccessControl::authenticate_user($username, $pw_or_ticket, $otp);
    }

    my %extra;
    my $ticket_data = $username;
    if (defined($tfa_info)) {
	$extra{NeedTFA} = 1;
	if ($tfa_info->{type} eq 'u2f') {
	    my $u2finfo = $tfa_info->{data};
	    my $u2f = get_u2f_instance($rpcenv, $u2finfo->@{qw(publicKey keyHandle)});
	    my $challenge = $u2f->auth_challenge()
		or die "failed to get u2f challenge\n";
	    $challenge = decode_json($challenge);
	    $extra{U2FChallenge} = $challenge;
	    $ticket_data = "u2f!$username!$challenge->{challenge}";
	} else {
	    # General half-login / 'missing 2nd factor' ticket:
	    $ticket_data = "tfa!$username";
	}
    }

    my $ticket = PVE::AccessControl::assemble_ticket($ticket_data);
    my $csrftoken = PVE::AccessControl::assemble_csrf_prevention_token($username);

    return {
	ticket => $ticket,
	username => $username,
	CSRFPreventionToken => $csrftoken,
	%extra,
    };
};

my $compute_api_permission = sub {
    my ($rpcenv, $authuser) = @_;

    my $usercfg = $rpcenv->{user_cfg};

    my $res = {};
    my $priv_re_map = {
	vms => qr/VM\.|Permissions\.Modify/,
	access => qr/(User|Group)\.|Permissions\.Modify/,
	storage => qr/Datastore\.|Permissions\.Modify/,
	nodes => qr/Sys\.|Permissions\.Modify/,
	dc => qr/Sys\.Audit/,
    };
    map { $res->{$_} = {} } keys %$priv_re_map;

    my $required_paths = ['/', '/nodes', '/access/groups', '/vms', '/storage'];

    my $checked_paths = {};
    foreach my $path (@$required_paths, keys %{$usercfg->{acl}}) {
	next if $checked_paths->{$path};
	$checked_paths->{$path} = 1;

	my $path_perm = $rpcenv->permissions($authuser, $path);

	my $toplevel = ($path =~ /^\/(\w+)/) ? $1 : 'dc';
	if ($toplevel eq 'pool') {
	    foreach my $priv (keys %$path_perm) {
		if ($priv =~ m/^VM\./) {
		    $res->{vms}->{$priv} = 1;
		} elsif ($priv =~ m/^Datastore\./) {
		    $res->{storage}->{$priv} = 1;
		} elsif ($priv eq 'Permissions.Modify') {
		    $res->{storage}->{$priv} = 1;
		    $res->{vms}->{$priv} = 1;
		}
	    }
	} else {
	    my $priv_regex = $priv_re_map->{$toplevel} // next;
	    foreach my $priv (keys %$path_perm) {
		next if $priv !~ m/^($priv_regex)/;
		$res->{$toplevel}->{$priv} = 1;
	    }
	}
    }

    return $res;
};

__PACKAGE__->register_method ({
    name => 'get_ticket', 
    path => 'ticket', 
    method => 'GET',
    permissions => { user => 'world' },
    description => "Dummy. Useful for formatters which want to provide a login page.",
    parameters => {
	additionalProperties => 0,
    },
    returns => { type => "null" },
    code => sub { return undef; }});
  
__PACKAGE__->register_method ({
    name => 'create_ticket', 
    path => 'ticket', 
    method => 'POST',
    permissions => { 
	description => "You need to pass valid credientials.",
	user => 'world' 
    },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to create tickets
    description => "Create or verify authentication ticket.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    username => {
	        description => "User name",
	        type => 'string',
	        maxLength => 64,
	        completion => \&PVE::AccessControl::complete_username,
	    },
	    realm =>  get_standard_option('realm', {
		description => "You can optionally pass the realm using this parameter. Normally the realm is simply added to the username <username>\@<relam>.",
		optional => 1,
		completion => \&PVE::AccessControl::complete_realm,
	    }),
	    password => { 
		description => "The secret password. This can also be a valid ticket.",
		type => 'string',
	    },
	    otp => {
		description => "One-time password for Two-factor authentication.",
		type => 'string',
		optional => 1,
	    },
	    path => {
		description => "Verify ticket, and check if user have access 'privs' on 'path'",
		type => 'string',
		requires => 'privs',
		optional => 1,
		maxLength => 64,
	    },
	    privs => { 
		description => "Verify ticket, and check if user have access 'privs' on 'path'",
		type => 'string' , format => 'pve-priv-list',
		requires => 'path',
		optional => 1,
		maxLength => 64,
	    },
	}
    },
    returns => {
	type => "object",
	properties => {
	    username => { type => 'string' },
	    ticket => { type => 'string', optional => 1},
	    CSRFPreventionToken => { type => 'string', optional => 1 },
	    clustername => { type => 'string', optional => 1 },
	    # cap => computed api permissions, unless there's a u2f challenge
	}
    },
    code => sub {
	my ($param) = @_;
    
	my $username = $param->{username};
	$username .= "\@$param->{realm}" if $param->{realm};

	my $rpcenv = PVE::RPCEnvironment::get();

	my $res;
	eval {
	    # test if user exists and is enabled
	    $rpcenv->check_user_enabled($username);

	    if ($param->{path} && $param->{privs}) {
		$res = &$verify_auth($rpcenv, $username, $param->{password}, $param->{otp},
				     $param->{path}, $param->{privs});
	    } else {
		$res = &$create_ticket($rpcenv, $username, $param->{password}, $param->{otp});
	    }
	};
	if (my $err = $@) {
	    my $clientip = $rpcenv->get_client_ip() || '';
	    syslog('err', "authentication failure; rhost=$clientip user=$username msg=$err");
	    # do not return any info to prevent user enumeration attacks
	    die PVE::Exception->new("authentication failure\n", code => 401);
	}

	$res->{cap} = &$compute_api_permission($rpcenv, $username)
	    if !defined($res->{NeedTFA});

	my $clinfo = PVE::Cluster::get_clinfo();
	if ($clinfo->{cluster}->{name} && $rpcenv->check($username, '/', ['Sys.Audit'], 1)) {
	    $res->{clustername} = $clinfo->{cluster}->{name};
	}

	PVE::Cluster::log_msg('info', 'root@pam', "successful auth for user '$username'");

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'change_password',
    path => 'password', 
    method => 'PUT',
    permissions => { 
	description => "Each user is allowed to change his own password. A user can change the password of another user if he has 'Realm.AllocateUser' (on the realm of user <userid>) and 'User.Modify' permission on /access/groups/<group> on a group where user <userid> is member of.",
	check => [ 'or', 
		   ['userid-param', 'self'],
		   [ 'and',
		     [ 'userid-param', 'Realm.AllocateUser'],
		     [ 'userid-group', ['User.Modify']]
		   ]
	    ],
    },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to change the regular user password
    description => "Change user password.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid-completed'),
	    password => { 
		description => "The new password.",
		type => 'string',
		minLength => 5, 
		maxLength => 64,
	    },
	}
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my ($userid, $ruid, $realm) = PVE::AccessControl::verify_username($param->{userid});

	$rpcenv->check_user_exist($userid);

	if ($authuser eq 'root@pam') {
	    # OK - root can change anything
	} else {
	    if ($authuser eq $userid) {
		$rpcenv->check_user_enabled($userid);
		# OK - each user can change its own password
	    } else {
		# only root may change root password
		raise_perm_exc() if $userid eq 'root@pam';
		# do not allow to change system user passwords
		raise_perm_exc() if $realm eq 'pam';
	    }
	}

	PVE::AccessControl::domain_set_password($realm, $ruid, $param->{password});

	PVE::Cluster::log_msg('info', 'root@pam', "changed password for user '$userid'");

	return undef;
    }});

sub get_u2f_config() {
    die "u2f support not available\n" if !$u2f_available;

    my $dc = cfs_read_file('datacenter.cfg');
    my $u2f = $dc->{u2f};
    die "u2f not configured in datacenter.cfg\n" if !$u2f;
    return $u2f;
}

sub get_u2f_instance {
    my ($rpcenv, $publicKey, $keyHandle) = @_;

    # We store the public key base64 encoded (as the api provides it in binary)
    $publicKey = decode_base64($publicKey) if defined($publicKey);

    my $u2fconfig = get_u2f_config();
    my $u2f = PVE::U2F->new();

    # via the 'Host' header (in case a node has multiple hosts available).
    my $origin = $u2fconfig->{origin};
    if (!defined($origin)) {
	$origin = $rpcenv->get_request_host(1);
	if ($origin) {
	    $origin = "https://$origin";
	} else {
	    die "failed to figure out u2f origin\n";
	}
    }

    my $appid = $u2fconfig->{appid} // $origin;
    $u2f->set_appid($appid);
    $u2f->set_origin($origin);
    $u2f->set_publicKey($publicKey) if defined($publicKey);
    $u2f->set_keyHandle($keyHandle) if defined($keyHandle);
    return $u2f;
}

sub verify_user_tfa_config {
    my ($type, $tfa_cfg, $value) = @_;

    if (!defined($type)) {
	die "missing tfa 'type'\n";
    }

    if ($type ne 'oath') {
	die "invalid type for custom tfa authentication\n";
    }

    my $secret = $tfa_cfg->{keys}
	or die "missing TOTP secret\n";
    $tfa_cfg = $tfa_cfg->{config};
    # Copy the hash to verify that we have no unexpected keys without modifying the original hash.
    $tfa_cfg = {%$tfa_cfg};

    # We can only verify 1 secret but oath_verify_otp allows multiple:
    if (scalar(PVE::Tools::split_list($secret)) != 1) {
	die "only exactly one secret key allowed\n";
    }

    my $digits = delete($tfa_cfg->{digits}) // 6;
    my $step = delete($tfa_cfg->{step}) // 30;
    # Maybe also this?
    #     my $algorithm = delete($tfa_cfg->{algorithm}) // 'sha1';

    if (length(my $more = join(', ', keys %$tfa_cfg))) {
	die "unexpected tfa config keys: $more\n";
    }

    PVE::OTP::oath_verify_otp($value, $secret, $step, $digits);
}

__PACKAGE__->register_method ({
    name => 'change_tfa',
    path => 'tfa',
    method => 'PUT',
    permissions => {
	description => 'A user can change their own u2f or totp token.',
	check => [ 'or',
		   ['userid-param', 'self'],
		   [ 'and',
		     [ 'userid-param', 'Realm.AllocateUser'],
		     [ 'userid-group', ['User.Modify']]
		   ]
	    ],
    },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to change the regular user's TFA settings
    description => "Change user u2f authentication.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid', {
		completion => \&PVE::AccessControl::complete_username,
	    }),
	    password => {
		optional => 1, # Only required if not root@pam
		description => "The current password.",
		type => 'string',
		minLength => 5,
		maxLength => 64,
	    },
	    action => {
		description => 'The action to perform',
		type => 'string',
		enum => [qw(delete new confirm)],
	    },
	    response => {
		optional => 1,
		description =>
		    'Either the the response to the current u2f registration challenge,'
		    .' or, when adding TOTP, the currently valid TOTP value.',
		type => 'string',
	    },
	    key => {
		optional => 1,
		description => 'When adding TOTP, the shared secret value.',
		type => 'string',
		format => 'pve-tfa-secret',
	    },
	    config => {
		optional => 1,
		description => 'A TFA configuration. This must currently be of type TOTP of not set at all.',
		type => 'string',
		format => 'pve-tfa-config',
		maxLength => 128,
	    },
	}
    },
    returns => { type => 'object' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $action = delete $param->{action};
	my $response = delete $param->{response};
	my $password = delete($param->{password}) // '';
	my $key = delete($param->{key});
	my $config = delete($param->{config});

	my ($userid, $ruid, $realm) = PVE::AccessControl::verify_username($param->{userid});
	$rpcenv->check_user_exist($userid);

	# Only root may modify root
	raise_perm_exc() if $userid eq 'root@pam' && $authuser ne 'root@pam';

	# Regular users need to confirm their password to change u2f settings.
	if ($authuser ne 'root@pam') {
	    raise_param_exc({ 'password' => 'password is required to modify u2f data' })
		if !defined($password);
	    my $domain_cfg = cfs_read_file('domains.cfg');
	    my $cfg = $domain_cfg->{ids}->{$realm};
	    die "auth domain '$realm' does not exist\n" if !$cfg;
	    my $plugin = PVE::Auth::Plugin->lookup($cfg->{type});
	    $plugin->authenticate_user($cfg, $realm, $ruid, $password);
	}

	if ($action eq 'delete') {
	    PVE::AccessControl::user_set_tfa($userid, $realm, undef, undef);
	    PVE::Cluster::log_msg('info', $authuser, "deleted u2f data for user '$userid'");
	} elsif ($action eq 'new') {
	    if (defined($config)) {
		$config = PVE::Auth::Plugin::parse_tfa_config($config);
		my $type = delete($config->{type});
		my $tfa_cfg = {
		    keys => $key,
		    config => $config,
		};
		verify_user_tfa_config($type, $tfa_cfg, $response);
		PVE::AccessControl::user_set_tfa($userid, $realm, $type, $tfa_cfg);
	    } else {
		# The default is U2F:
		my $u2f = get_u2f_instance($rpcenv);
		my $challenge = $u2f->registration_challenge()
		    or raise("failed to get u2f challenge");
		$challenge = decode_json($challenge);
		PVE::AccessControl::user_set_tfa($userid, $realm, 'u2f', $challenge);
		return $challenge;
	    }
	} elsif ($action eq 'confirm') {
	    raise_param_exc({ 'response' => "confirm action requires the 'response' parameter to be set" })
		if !defined($response);

	    my ($type, $u2fdata) = PVE::AccessControl::user_get_tfa($userid, $realm);
	    raise("no u2f data available")
		if (!defined($type) || $type ne 'u2f');

	    my $challenge = $u2fdata->{challenge}
		or raise("no active challenge");

	    my $u2f = get_u2f_instance($rpcenv);
	    $u2f->set_challenge($challenge);
	    my ($keyHandle, $publicKey) = $u2f->registration_verify($response);
	    PVE::AccessControl::user_set_tfa($userid, $realm, 'u2f', {
		keyHandle => $keyHandle,
		publicKey => $publicKey, # already base64 encoded
	    });
	} else {
	    die "invalid action: $action\n";
	}

	return {};
    }});

__PACKAGE__->register_method({
    name => 'verify_tfa',
    path => 'tfa',
    method => 'POST',
    permissions => { user => 'all' },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to access TFA information
    description => 'Finish a u2f challenge.',
    parameters => {
	additionalProperties => 0,
	properties => {
	    response => {
		type => 'string',
		description => 'The response to the current authentication challenge.',
	    },
	}
    },
    returns => {
	type => 'object',
	properties => {
	    ticket => { type => 'string' },
	    # cap
	}
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();
	my ($username, undef, $realm) = PVE::AccessControl::verify_username($authuser);

	my ($tfa_type, $tfa_data) = PVE::AccessControl::user_get_tfa($username, $realm);
	if (!defined($tfa_type)) {
	    raise('no u2f data available');
	}

	eval {
	    if ($tfa_type eq 'u2f') {
		my $challenge = $rpcenv->get_u2f_challenge()
		   or raise('no active challenge');

		my $keyHandle = $tfa_data->{keyHandle};
		my $publicKey = $tfa_data->{publicKey};
		raise("incomplete u2f setup")
		    if !defined($keyHandle) || !defined($publicKey);

		my $u2f = get_u2f_instance($rpcenv, $publicKey, $keyHandle);
		$u2f->set_challenge($challenge);

		my ($counter, $present) = $u2f->auth_verify($param->{response});
		# Do we want to do anything with these?
	    } else {
		# sanity check before handing off to the verification code:
		my $keys = $tfa_data->{keys} or die "missing tfa keys\n";
		my $config = $tfa_data->{config} or die "bad tfa entry\n";
		PVE::AccessControl::verify_one_time_pw($tfa_type, $authuser, $keys, $config, $param->{response});
	    }
	};
	if (my $err = $@) {
	    my $clientip = $rpcenv->get_client_ip() || '';
	    syslog('err', "authentication verification failure; rhost=$clientip user=$authuser msg=$err");
	    die PVE::Exception->new("authentication failure\n", code => 401);
	}

	return {
	    ticket => PVE::AccessControl::assemble_ticket($authuser),
	    cap => &$compute_api_permission($rpcenv, $authuser),
	}
    }});

__PACKAGE__->register_method({
    name => 'permissions',
    path => 'permissions',
    method => 'GET',
    description => 'Retrieve effective permissions of given user/token.',
    permissions => {
	description => "Each user/token is allowed to dump their own permissions. A user can dump the permissions of another user if they have 'Sys.Audit' permission on /access.",
	user => 'all',
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => {
		type => 'string',
		description => "User ID or full API token ID",
		pattern => $PVE::AccessControl::userid_or_token_regex,
		optional => 1,
	    },
	    path => get_standard_option('acl-path', {
		description => "Only dump this specific path, not the whole tree.",
		optional => 1,
	    }),
	},
    },
    returns => {
	type => 'object',
	description => 'Map of "path" => (Map of "privilege" => "propagate boolean").',
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $userid = $param->{userid};
	if (defined($userid)) {
	    $rpcenv->check($rpcenv->get_user(), '/access', ['Sys.Audit']);
	} else {
	    $userid = $rpcenv->get_user();
	}

	my $res;

	if (my $path = $param->{path}) {
	    my $perms = $rpcenv->permissions($userid, $path);
	    if ($perms) {
		$res = { $path => $perms };
	    } else {
		$res = {};
	    }
	} else {
	    $res = $rpcenv->get_effective_permissions($userid);
	}

	return $res;
    }});

1;

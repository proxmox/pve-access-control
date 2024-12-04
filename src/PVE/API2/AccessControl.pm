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
use PVE::API2::OpenId;
use PVE::API2::TFA;
use PVE::Auth::Plugin;
use PVE::OTP;

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
    subclass => "PVE::API2::OpenId",
    path => 'openid',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::TFA",
    path => 'tfa',
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


my sub verify_auth : prototype($$$$$$) {
    my ($rpcenv, $username, $pw_or_ticket, $otp, $path, $privs) = @_;

    my $normpath = PVE::AccessControl::normalize_path($path);
    die "invalid path - $path\n" if defined($path) && !defined($normpath);

    my $ticketuser;
    if (($ticketuser = PVE::AccessControl::verify_ticket($pw_or_ticket, 1)) &&
	($ticketuser eq $username)) {
	# valid ticket
    } elsif (PVE::AccessControl::verify_vnc_ticket($pw_or_ticket, $username, $normpath, 1)) {
	# valid vnc ticket
    } else {
	$username = PVE::AccessControl::authenticate_user(
	    $username,
	    $pw_or_ticket,
	    $otp,
	);
    }

    my $privlist = [ PVE::Tools::split_list($privs) ];
    if (!($normpath && scalar(@$privlist) && $rpcenv->check($username, $normpath, $privlist))) {
	die "no permission ($path, $privs)\n";
    }

    return { username => $username };
};

my sub create_ticket_do : prototype($$$$$) {
    my ($rpcenv, $username, $pw_or_ticket, $otp, $tfa_challenge) = @_;

    die "TFA response should be in 'password', not 'otp' when 'tfa-challenge' is set\n"
	if defined($otp) && defined($tfa_challenge);

    my ($ticketuser, undef, $tfa_info);
    if (!defined($tfa_challenge)) {
	# We only verify this ticket if we're not responding to a TFA challenge, as in that case
	# it is a TFA-data ticket and will be verified by `authenticate_user`.

	($ticketuser, undef, $tfa_info) = PVE::AccessControl::verify_ticket($pw_or_ticket, 1);
    }

    if (defined($ticketuser) && ($ticketuser eq 'root@pam' || $ticketuser eq $username)) {
	if (defined($tfa_info)) {
	    die "incomplete ticket\n";
	}
	# valid ticket. Note: root@pam can create tickets for other users
    } else {
	($username, $tfa_info) = PVE::AccessControl::authenticate_user(
	    $username,
	    $pw_or_ticket,
	    $otp,
	    $tfa_challenge,
	);
    }

    my %extra;
    my $ticket_data = $username;
    my $aad;
    if (defined($tfa_info)) {
	$extra{NeedTFA} = 1;
	$ticket_data = "!tfa!$tfa_info";
	$aad = $username;
    }

    my $ticket = PVE::AccessControl::assemble_ticket($ticket_data, $aad);
    my $csrftoken = PVE::AccessControl::assemble_csrf_prevention_token($username);

    return {
	ticket => $ticket,
	username => $username,
	CSRFPreventionToken => $csrftoken,
	%extra,
    };
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
		description => "You can optionally pass the realm using this parameter. Normally"
		    ." the realm is simply added to the username <username>\@<realm>.",
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
	    'new-format' => {
		type => 'boolean',
		description => 'This parameter is now ignored and assumed to be 1.',
		optional => 1,
		default => 1,
	    },
	    'tfa-challenge' => {
		type => 'string',
                description => "The signed TFA challenge string the user wants to respond to.",
		optional => 1,
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

	$username = PVE::AccessControl::lookup_username($username);
	my $rpcenv = PVE::RPCEnvironment::get();

	my $res;
	eval {
	    # test if user exists and is enabled
	    $rpcenv->check_user_enabled($username);

	    if ($param->{path} && $param->{privs}) {
		$res = verify_auth($rpcenv, $username, $param->{password}, $param->{otp},
				   $param->{path}, $param->{privs});
	    } else {
		$res = create_ticket_do(
		    $rpcenv,
		    $username,
		    $param->{password},
		    $param->{otp},
		    $param->{'tfa-challenge'},
		);
	    }
	};
	if (my $err = $@) {
	    my $clientip = $rpcenv->get_client_ip() || '';
	    syslog('err', "authentication failure; rhost=$clientip user=$username msg=$err");
	    # do not return any info to prevent user enumeration attacks
	    die PVE::Exception->new("authentication failure\n", code => 401);
	}

	$res->{cap} = $rpcenv->compute_api_permission($username)
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
	description => "Each user is allowed to change their own password. A user can change the"
	    ." password of another user if they have 'Realm.AllocateUser' (on the realm of user"
	    ." <userid>) and 'User.Modify' permission on /access/groups/<group> on a group where"
	    ." user <userid> is member of. For the PAM realm, a password change does not take "
	    ." effect cluster-wide, but only applies to the local node.",
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
		minLength => 8,
		maxLength => 64,
	    },
	    'confirmation-password' => $PVE::API2::TFA::OPTIONAL_PASSWORD_SCHEMA,
	}
    },
    returns => { type => "null" },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my ($userid, $ruid, $realm) = $rpcenv->reauth_user_for_user_modification(
	    $authuser,
	    $param->{userid},
	    $param->{'confirmation-password'},
	    'confirmation-password',
	);

	if ($authuser eq 'root@pam') {
	    # OK - root can change anything
	} else {
	    if ($authuser eq $userid) {
		$rpcenv->check_user_enabled($userid);
		# OK - each user can change their own password
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


__PACKAGE__->register_method({
    name => 'permissions',
    path => 'permissions',
    method => 'GET',
    description => 'Retrieve effective permissions of given user/token.',
    permissions => {
	description => "Each user/token is allowed to dump their own permissions (or that of owned"
	    ." tokens). A user can dump the permissions of another user or their tokens if they"
	    ." have 'Sys.Audit' permission on /access.",
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
	my $authid = $rpcenv->get_user();

	my $userid = $param->{userid};
	$userid = $authid if !defined($userid);

	my ($user, $token) = PVE::AccessControl::split_tokenid($userid, 1);
	my $check_self = $userid eq $authid;
	my $check_owned_token = defined($user) && $user eq $authid;

	if (!($check_self || $check_owned_token)) {
	    $rpcenv->check($rpcenv->get_user(), '/access', ['Sys.Audit']);
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

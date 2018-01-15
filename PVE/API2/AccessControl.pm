package PVE::API2::AccessControl;

use strict;
use warnings;

use PVE::Exception qw(raise raise_perm_exc);
use PVE::SafeSyslog;
use PVE::RPCEnvironment;
use PVE::Cluster qw(cfs_read_file);
use PVE::RESTHandler;
use PVE::AccessControl;
use PVE::JSONSchema qw(get_standard_option);
use PVE::API2::Domains;
use PVE::API2::User;
use PVE::API2::Group;
use PVE::API2::Role;
use PVE::API2::ACL;

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

    my $ticketuser;
    if (($ticketuser = PVE::AccessControl::verify_ticket($pw_or_ticket, 1)) &&
	($ticketuser eq 'root@pam' || $ticketuser eq $username)) {
	# valid ticket. Note: root@pam can create tickets for other users
    } else {
	$username = PVE::AccessControl::authenticate_user($username, $pw_or_ticket, $otp);
    }

    my $ticket = PVE::AccessControl::assemble_ticket($username);
    my $csrftoken = PVE::AccessControl::assemble_csrf_prevention_token($username);

    return {
	ticket => $ticket,
	username => $username,
	CSRFPreventionToken => $csrftoken,
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

	$res->{cap} = &$compute_api_permission($rpcenv, $username);

	PVE::Cluster::log_msg('info', 'root@pam', "successful auth for user '$username'");

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'change_passsword', 
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
    description => "Change user password.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid', {
		completion => \&PVE::AccessControl::complete_username,
	    }),
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

1;

package PVE::API2::User;

use strict;
use warnings;
use PVE::Exception qw(raise raise_perm_exc);
use PVE::Cluster qw (cfs_read_file cfs_write_file);
use PVE::Tools qw(split_list);
use PVE::AccessControl;
use PVE::JSONSchema qw(get_standard_option);

use PVE::SafeSyslog;

use PVE::RESTHandler;

use base qw(PVE::RESTHandler);

my $extract_user_data = sub {
    my ($data, $full) = @_;

    my $res = {};

    foreach my $prop (qw(enable expire firstname lastname email comment keys)) {
	$res->{$prop} = $data->{$prop} if defined($data->{$prop});
    }

    return $res if !$full;

    $res->{groups} = $data->{groups} ? [ keys %{$data->{groups}} ] : [];

    return $res;
};

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "User index.",
    permissions => {
	description => "The returned list is restricted to users where you have 'User.Modify' or 'Sys.Audit' permissions on '/access/groups' or on a group the user belongs too. But it always includes the current (authenticated) user.",
	user => 'all',
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    enabled => {
		type => 'boolean',
		description => "Optional filter for enable property.",
		optional => 1,
	    }
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		userid => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{userid}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $usercfg = $rpcenv->{user_cfg};
	my $authuser = $rpcenv->get_user();

	my $res = [];

	my $privs = [ 'User.Modify', 'Sys.Audit' ];
	my $canUserMod = $rpcenv->check_any($authuser, "/access/groups", $privs, 1);
	my $groups = $rpcenv->filter_groups($authuser, $privs, 1);
	my $allowed_users = $rpcenv->group_member_join([keys %$groups]);

	foreach my $user (keys %{$usercfg->{users}}) {

	    if (!($canUserMod || $user eq $authuser)) {
		next if !$allowed_users->{$user};
	    }

	    my $entry = &$extract_user_data($usercfg->{users}->{$user});

	    if (defined($param->{enabled})) {
		next if $entry->{enable} && !$param->{enabled};
		next if !$entry->{enable} && $param->{enabled};
	    }

	    $entry->{userid} = $user;
	    push @$res, $entry;
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'create_user',
    protected => 1,
    path => '',
    method => 'POST',
    permissions => {
	description => "You need 'Realm.AllocateUser' on '/access/realm/<realm>' on the realm of user <userid>, and 'User.Modify' permissions to '/access/groups/<group>' for any group specified (or 'User.Modify' on '/access/groups' if you pass no groups.",
	check => [ 'and',
		   [ 'userid-param', 'Realm.AllocateUser'],
		   [ 'userid-group', ['User.Modify'], groups_param => 1],
	    ],
    },
    description => "Create new user.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	    password => {
		description => "Initial password.",
		type => 'string',
		optional => 1,
		minLength => 5,
		maxLength => 64
	    },
	    groups => {
		type => 'string', format => 'pve-groupid-list',
		optional => 1,
		completion => \&PVE::AccessControl::complete_group,
	    },
	    firstname => { type => 'string', optional => 1 },
	    lastname => { type => 'string', optional => 1 },
	    email => { type => 'string', optional => 1, format => 'email-opt' },
	    comment => { type => 'string', optional => 1 },
	    keys => {
		description => "Keys for two factor auth (yubico).",
		type => 'string',
		optional => 1,
	    },
	    expire => {
		description => "Account expiration date (seconds since epoch). '0' means no expiration date.",
		type => 'integer',
		minimum => 0,
		optional => 1,
	    },
	    enable => {
		description => "Enable the account (default). You can set this to '0' to disable the accout",
		type => 'boolean',
		optional => 1,
		default => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PVE::AccessControl::lock_user_config(
	    sub {

		my ($username, $ruid, $realm) = PVE::AccessControl::verify_username($param->{userid});

		my $usercfg = cfs_read_file("user.cfg");

		die "user '$username' already exists\n"
		    if $usercfg->{users}->{$username};

		PVE::AccessControl::domain_set_password($realm, $ruid, $param->{password})
		    if defined($param->{password});

		my $enable = defined($param->{enable}) ? $param->{enable} : 1;
		$usercfg->{users}->{$username} = { enable => $enable };
		$usercfg->{users}->{$username}->{expire} = $param->{expire} if $param->{expire};

		if ($param->{groups}) {
		    foreach my $group (split_list($param->{groups})) {
			if ($usercfg->{groups}->{$group}) {
			    PVE::AccessControl::add_user_group($username, $usercfg, $group);
			} else {
			    die "no such group '$group'\n";
			}
		    }
		}

		$usercfg->{users}->{$username}->{firstname} = $param->{firstname} if $param->{firstname};
		$usercfg->{users}->{$username}->{lastname} = $param->{lastname} if $param->{lastname};
		$usercfg->{users}->{$username}->{email} = $param->{email} if $param->{email};
		$usercfg->{users}->{$username}->{comment} = $param->{comment} if $param->{comment};
		$usercfg->{users}->{$username}->{keys} = $param->{keys} if $param->{keys};

		cfs_write_file("user.cfg", $usercfg);
	    }, "create user failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'read_user',
    path => '{userid}',
    method => 'GET',
    description => "Get user configuration.",
    permissions => {
	check => ['userid-group', ['User.Modify', 'Sys.Audit']],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	},
    },
    returns => {
	additionalProperties => 0,
	properties => {
	    enable => { type => 'boolean' },
	    expire => { type => 'integer', optional => 1 },
	    firstname => { type => 'string', optional => 1 },
	    lastname => { type => 'string', optional => 1 },
	    email => { type => 'string', optional => 1 },
	    comment => { type => 'string', optional => 1 },
	    keys => { type => 'string', optional => 1 },
	    groups => { type => 'array' },
	}
    },
    code => sub {
	my ($param) = @_;

	my ($username, undef, $domain) =
	    PVE::AccessControl::verify_username($param->{userid});

	my $usercfg = cfs_read_file("user.cfg");

	my $data = PVE::AccessControl::check_user_exist($usercfg, $username);

	return &$extract_user_data($data, 1);
    }});

__PACKAGE__->register_method ({
    name => 'update_user',
    protected => 1,
    path => '{userid}',
    method => 'PUT',
    permissions => {
	check => ['userid-group', ['User.Modify'], groups_param => 1 ],
    },
    description => "Update user configuration.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid', {
		completion => \&PVE::AccessControl::complete_username,
	    }),
	    groups => {
		type => 'string', format => 'pve-groupid-list',
		optional => 1,
		completion => \&PVE::AccessControl::complete_group,
	    },
	    append => {
		type => 'boolean',
		optional => 1,
		requires => 'groups',
	    },
	    enable => {
		description => "Enable/disable the account.",
		type => 'boolean',
		optional => 1,
	    },
	    firstname => { type => 'string', optional => 1 },
	    lastname => { type => 'string', optional => 1 },
	    email => { type => 'string', optional => 1, format => 'email-opt' },
	    comment => { type => 'string', optional => 1 },
	    keys => {
		description => "Keys for two factor auth (yubico).",
		type => 'string',
		optional => 1,
	    },
	    expire => {
		description => "Account expiration date (seconds since epoch). '0' means no expiration date.",
		type => 'integer',
		minimum => 0,
		optional => 1
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my ($username, $ruid, $realm) =
	    PVE::AccessControl::verify_username($param->{userid});

	PVE::AccessControl::lock_user_config(
	    sub {

		my $usercfg = cfs_read_file("user.cfg");

		PVE::AccessControl::check_user_exist($usercfg, $username);

		$usercfg->{users}->{$username}->{enable} = $param->{enable} if defined($param->{enable});

		$usercfg->{users}->{$username}->{expire} = $param->{expire} if defined($param->{expire});

		PVE::AccessControl::delete_user_group($username, $usercfg)
		    if (!$param->{append} && defined($param->{groups}));

		if ($param->{groups}) {
		    foreach my $group (split_list($param->{groups})) {
			if ($usercfg->{groups}->{$group}) {
			    PVE::AccessControl::add_user_group($username, $usercfg, $group);
			} else {
			    die "no such group '$group'\n";
			}
		    }
		}

		$usercfg->{users}->{$username}->{firstname} = $param->{firstname} if defined($param->{firstname});
		$usercfg->{users}->{$username}->{lastname} = $param->{lastname} if defined($param->{lastname});
		$usercfg->{users}->{$username}->{email} = $param->{email} if defined($param->{email});
		$usercfg->{users}->{$username}->{comment} = $param->{comment} if defined($param->{comment});
		$usercfg->{users}->{$username}->{keys} = $param->{keys} if defined($param->{keys});

		cfs_write_file("user.cfg", $usercfg);
	    }, "update user failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete_user',
    protected => 1,
    path => '{userid}',
    method => 'DELETE',
    description => "Delete user.",
    permissions => {
	check => [ 'and',
		   [ 'userid-param', 'Realm.AllocateUser'],
		   [ 'userid-group', ['User.Modify']],
	    ],
    },
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid', {
		completion => \&PVE::AccessControl::complete_username,
	    }),
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my ($userid, $ruid, $realm) =
	    PVE::AccessControl::verify_username($param->{userid});

	PVE::AccessControl::lock_user_config(
	    sub {

		my $usercfg = cfs_read_file("user.cfg");

		my $domain_cfg = cfs_read_file('domains.cfg');
		if (my $cfg = $domain_cfg->{ids}->{$realm}) {
		    my $plugin = PVE::Auth::Plugin->lookup($cfg->{type});
		    $plugin->delete_user($cfg, $realm, $ruid);
		}

		delete $usercfg->{users}->{$userid};

		PVE::AccessControl::delete_user_group($userid, $usercfg);
		PVE::AccessControl::delete_user_acl($userid, $usercfg);

		cfs_write_file("user.cfg", $usercfg);
	    }, "delete user failed");

	return undef;
    }});

1;

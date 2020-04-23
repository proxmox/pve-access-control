package PVE::API2::Domains;

use strict;
use warnings;

use PVE::Exception qw(raise_param_exc);
use PVE::Tools qw(extract_param);
use PVE::Cluster qw (cfs_read_file cfs_write_file);
use PVE::AccessControl;
use PVE::JSONSchema qw(get_standard_option);

use PVE::SafeSyslog;
use PVE::RESTHandler;
use PVE::Auth::Plugin;

my $domainconfigfile = "domains.cfg";

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Authentication domain index.",
    permissions => {
	description => "Anyone can access that, because we need that list for the login box (before the user is authenticated).",
	user => 'world',
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
		realm => { type => 'string' },
		type => { type => 'string' },
		tfa => {
		    description => "Two-factor authentication provider.",
		    type => 'string',
		    enum => [ 'yubico', 'oath' ],
		    optional => 1,
		},
		comment => {
		    description => "A comment. The GUI use this text when you select a domain (Realm) on the login window.",
		    type => 'string',
		    optional => 1,
		},
	    },
	},
	links => [ { rel => 'child', href => "{realm}" } ],
    },
    code => sub {
	my ($param) = @_;

	my $res = [];

	my $cfg = cfs_read_file($domainconfigfile);
	my $ids = $cfg->{ids};

	foreach my $realm (keys %$ids) {
	    my $d = $ids->{$realm};
	    my $entry = { realm => $realm, type => $d->{type} };
	    $entry->{comment} = $d->{comment} if $d->{comment};
	    $entry->{default} = 1 if $d->{default};
	    if ($d->{tfa} && (my $tfa_cfg = PVE::Auth::Plugin::parse_tfa_config($d->{tfa}))) {
		$entry->{tfa} = $tfa_cfg->{type};
	    }
	    push @$res, $entry;
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'create',
    protected => 1,
    path => '',
    method => 'POST',
    permissions => {
	check => ['perm', '/access/realm', ['Realm.Allocate']],
    },
    description => "Add an authentication server.",
    parameters => PVE::Auth::Plugin->createSchema(),
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	# always extract, add it with hook
	my $password = extract_param($param, 'password');

	PVE::Auth::Plugin::lock_domain_config(
	    sub {

		my $cfg = cfs_read_file($domainconfigfile);
		my $ids = $cfg->{ids};

		my $realm = extract_param($param, 'realm');
		my $type = $param->{type};

		die "domain '$realm' already exists\n"
		    if $ids->{$realm};

		die "unable to use reserved name '$realm'\n"
		    if ($realm eq 'pam' || $realm eq 'pve');

		die "unable to create builtin type '$type'\n"
		    if ($type eq 'pam' || $type eq 'pve');

		my $plugin = PVE::Auth::Plugin->lookup($type);
		my $config = $plugin->check_config($realm, $param, 1, 1);

		if ($config->{default}) {
		    foreach my $r (keys %$ids) {
			delete $ids->{$r}->{default};
		    }
		}

		$ids->{$realm} = $config;

		my $opts = $plugin->options();
		if (defined($password) && !defined($opts->{password})) {
		    $password = undef;
		    warn "ignoring password parameter";
		}
		$plugin->on_add_hook($realm, $config, password => $password);

		cfs_write_file($domainconfigfile, $cfg);
	    }, "add auth server failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'update',
    path => '{realm}',
    method => 'PUT',
    permissions => {
	check => ['perm', '/access/realm', ['Realm.Allocate']],
    },
    description => "Update authentication server settings.",
    protected => 1,
    parameters => PVE::Auth::Plugin->updateSchema(),
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	# always extract, update in hook
	my $password = extract_param($param, 'password');

	PVE::Auth::Plugin::lock_domain_config(
	    sub {

		my $cfg = cfs_read_file($domainconfigfile);
		my $ids = $cfg->{ids};

		my $digest = extract_param($param, 'digest');
		PVE::SectionConfig::assert_if_modified($cfg, $digest);

		my $realm = extract_param($param, 'realm');

		die "domain '$realm' does not exist\n"
		    if !$ids->{$realm};

		my $delete_str = extract_param($param, 'delete');
		die "no options specified\n" if !$delete_str && !scalar(keys %$param);

		my $delete_pw = 0;
		foreach my $opt (PVE::Tools::split_list($delete_str)) {
		    delete $ids->{$realm}->{$opt};
		    $delete_pw = 1 if $opt eq 'password';
		}

		my $plugin = PVE::Auth::Plugin->lookup($ids->{$realm}->{type});
		my $config = $plugin->check_config($realm, $param, 0, 1);

		if ($config->{default}) {
		    foreach my $r (keys %$ids) {
			delete $ids->{$r}->{default};
		    }
		}

		foreach my $p (keys %$config) {
		    $ids->{$realm}->{$p} = $config->{$p};
		}

		my $opts = $plugin->options();
		if ($delete_pw || defined($password)) {
		    $plugin->on_update_hook($realm, $config, password => $password);
		} else {
		    $plugin->on_update_hook($realm, $config);
		}

		cfs_write_file($domainconfigfile, $cfg);
	    }, "update auth server failed");

	return undef;
    }});

# fixme: return format!
__PACKAGE__->register_method ({
    name => 'read',
    path => '{realm}',
    method => 'GET',
    description => "Get auth server configuration.",
    permissions => {
	check => ['perm', '/access/realm', ['Realm.Allocate', 'Sys.Audit'], any => 1],
    },
    parameters => {
   	additionalProperties => 0,
	properties => {
	    realm =>  get_standard_option('realm'),
	},
    },
    returns => {},
    code => sub {
	my ($param) = @_;

	my $cfg = cfs_read_file($domainconfigfile);

	my $realm = $param->{realm};

	my $data = $cfg->{ids}->{$realm};
	die "domain '$realm' does not exist\n" if !$data;

	$data->{digest} = $cfg->{digest};

	return $data;
    }});


__PACKAGE__->register_method ({
    name => 'delete',
    path => '{realm}',
    method => 'DELETE',
    permissions => {
	check => ['perm', '/access/realm', ['Realm.Allocate']],
    },
    description => "Delete an authentication server.",
    protected => 1,
    parameters => {
   	additionalProperties => 0,
	properties => {
	    realm =>  get_standard_option('realm'),
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PVE::Auth::Plugin::lock_domain_config(
	    sub {

		my $cfg = cfs_read_file($domainconfigfile);
		my $ids = $cfg->{ids};
		my $realm = $param->{realm};

		die "authentication domain '$realm' does not exist\n" if !$ids->{$realm};

		my $plugin = PVE::Auth::Plugin->lookup($ids->{$realm}->{type});

		$plugin->on_delete_hook($realm, $ids->{$realm});

		delete $ids->{$realm};

		cfs_write_file($domainconfigfile, $cfg);
	    }, "delete auth server failed");

	return undef;
    }});

my $update_users = sub {
    my ($usercfg, $realm, $synced_users, $opts) = @_;

    print "syncing users\n";
    $usercfg->{users} = {} if !defined($usercfg->{users});
    my $users = $usercfg->{users};

    my $oldusers = {};
    if ($opts->{'full'}) {
	print "full sync, deleting outdated existing users first\n";
	foreach my $userid (sort keys %$users) {
	    next if $userid !~ m/\@$realm$/;

	    $oldusers->{$userid} = delete $users->{$userid};
	    if ($opts->{'purge'} && !$synced_users->{$userid}) {
		PVE::AccessControl::delete_user_acl($userid, $usercfg);
		print "purged user '$userid' and all its ACL entries\n";
	    } elsif (!defined($synced_users->{$userid})) {
		print "remove user '$userid'\n";
	    }
	}
    }

    foreach my $userid (sort keys %$synced_users) {
	my $synced_user = $synced_users->{$userid} // {};
	if (!defined($users->{$userid})) {
	    my $user = $users->{$userid} = $synced_user;

	    my $olduser = $oldusers->{$userid} // {};
	    if (defined(my $enabled = $olduser->{enable})) {
		$user->{enable} = $enabled;
	    } elsif ($opts->{'enable-new'}) {
		$user->{enable} = 1;
	    }

	    if (defined($olduser->{tokens})) {
		$user->{tokens} = $olduser->{tokens};
	    }
	    if (defined($oldusers->{$userid})) {
		print "updated user '$userid'\n";
	    } else {
		print "added user '$userid'\n";
	    }
	} else {
	    my $olduser = $users->{$userid};
	    foreach my $attr (keys %$synced_user) {
		$olduser->{$attr} = $synced_user->{$attr};
	    }
	    print "updated user '$userid'\n";
	}
    }
};

my $update_groups = sub {
    my ($usercfg, $realm, $synced_groups, $opts) = @_;

    print "syncing groups\n";
    $usercfg->{groups} = {} if !defined($usercfg->{groups});
    my $groups = $usercfg->{groups};
    my $oldgroups = {};

    if ($opts->{full}) {
	print "full sync, deleting outdated existing groups first\n";
	foreach my $groupid (sort keys %$groups) {
	    next if $groupid !~ m/\-$realm$/;

	    my $oldgroups->{$groupid} = delete $groups->{$groupid};
	    if ($opts->{purge} && !$synced_groups->{$groupid}) {
		print "purged group '$groupid' and all its ACL entries\n";
		PVE::AccessControl::delete_group_acl($groupid, $usercfg)
	    } elsif (!defined($synced_groups->{$groupid})) {
		print "removed group '$groupid'\n";
	    }
	}
    }

    foreach my $groupid (sort keys %$synced_groups) {
	my $synced_group = $synced_groups->{$groupid};
	if (!defined($groups->{$groupid})) {
	    $groups->{$groupid} = $synced_group;
	    if (defined($oldgroups->{$groupid})) {
		print "updated group '$groupid'\n";
	    } else {
		print "added group '$groupid'\n";
	    }
	} else {
	    my $group = $groups->{$groupid};
	    foreach my $attr (keys %$synced_group) {
		$group->{$attr} = $synced_group->{$attr};
	    }
	    print "updated group '$groupid'\n";
	}
    }
};

my $parse_sync_opts = sub {
    my ($param, $realmconfig) = @_;

    my $sync_opts_fmt = PVE::JSONSchema::get_format('realm-sync-options');

    my $res = {};
    my $defaults = {};
    if (defined(my $cfg_opts = $realmconfig->{'sync-defaults-options'})) {
	$defaults = PVE::JSONSchema::parse_property_string($sync_opts_fmt, $cfg_opts);
    }

    for my $opt (sort keys %$sync_opts_fmt) {
	my $fmt = $sync_opts_fmt->{$opt};

	$res->{$opt} = $param->{$opt} // $defaults->{$opt} // $fmt->{default};
	raise_param_exc({
	    "$opt" => 'Not passed as parameter and not defined in realm default sync options.'
	}) if !defined($res->{$opt});
    }
    return $res;
};

__PACKAGE__->register_method ({
    name => 'sync',
    path => '{realm}/sync',
    method => 'POST',
    permissions => {
	description => "'Realm.AllocateUser' on '/access/realm/<realm>' and "
	    ." 'User.Modify' permissions to '/access/groups/'.",
	check => [ 'and',
	    [ 'userid-param', 'Realm.AllocateUser' ],
	    [ 'userid-group', ['User.Modify'] ],
	],
    },
    description => "Syncs users and/or groups from the configured LDAP to user.cfg."
	." NOTE: Synced groups will have the name 'name-\$realm', so make sure"
	." those groups do not exist to prevent overwriting.",
    protected => 1,
    parameters => {
	additionalProperties => 0,
	properties => get_standard_option('realm-sync-options', {
	    realm => get_standard_option('realm'),
	})
    },
    returns => {
	description => 'Worker Task-UPID',
	type => 'string'
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();

	my $realm = $param->{realm};
	my $cfg = cfs_read_file($domainconfigfile);
	my $realmconfig = $cfg->{ids}->{$realm};

	raise_param_exc({ 'realm' => 'Realm does not exist.' }) if !defined($realmconfig);
	my $type = $realmconfig->{type};

	if ($type ne 'ldap' && $type ne 'ad') {
	    die "Cannot sync realm type '$type'! Only LDAP/AD realms can be synced.\n";
	}

	my $opts = $parse_sync_opts->($param, $realmconfig); # can throw up

	my $scope = $opts->{scope};
	my $whatstring = $scope eq 'both' ? "users and groups" : $scope;

	my $plugin = PVE::Auth::Plugin->lookup($type);

	my $worker = sub {
	    print "starting sync for realm $realm\n";

	    my ($synced_users, $dnmap) = $plugin->get_users($realmconfig, $realm);
	    my $synced_groups = {};
	    if ($scope eq 'groups' || $scope eq 'both') {
		$synced_groups = $plugin->get_groups($realmconfig, $realm, $dnmap);
	    }

	    PVE::AccessControl::lock_user_config(sub {
		my $usercfg = cfs_read_file("user.cfg");
		print "got data from server, updating $whatstring\n";

		if ($scope eq 'users' || $scope eq 'both') {
		    $update_users->($usercfg, $realm, $synced_users, $opts);
		}

		if ($scope eq 'groups' || $scope eq 'both') {
		    $update_groups->($usercfg, $realm, $synced_groups, $opts);
		}

		cfs_write_file("user.cfg", $usercfg);
		print "successfully updated $whatstring configuration\n";
	    }, "syncing $whatstring failed");
	};

	return $rpcenv->fork_worker('auth-realm-sync', $realm, $authuser, $worker);
    }});

1;

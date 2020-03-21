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

		foreach my $opt (PVE::Tools::split_list($delete_str)) {
		    delete $ids->{$realm}->{$opt};
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

		die "domain '$realm' does not exist\n" if !$ids->{$realm};

		delete $ids->{$realm};

		cfs_write_file($domainconfigfile, $cfg);
	    }, "delete auth server failed");

	return undef;
    }});

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
	properties => {
	    realm =>  get_standard_option('realm'),
	    scope => {
		description => "Select what to sync.",
		type => 'string',
		enum => [qw(users groups both)],
	    },
	    full => {
		description => "If set, uses the LDAP Directory as source of truth, ".
			       "deleting all information not contained there. ".
			       "Otherwise only syncs information set explicitly.",
		type => 'boolean',
	    },
	    enable => {
		description => "Enable newly synced users.",
		type => 'boolean',
	    },
	    purge => {
		description => "Remove ACLs for users/groups that were removed from the config.",
		type => 'boolean',
	    },
	}
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


	my $scope = $param->{scope};
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

		if ($sync_users) {
		    print "syncing users\n";
		    my $oldusers = $usercfg->{users};

		    my $oldtokens = {};
		    my $oldenabled = {};

		    if ($param->{full}) {
			print "full sync, deleting existing users first\n";
			foreach my $userid (keys %$oldusers) {
			    next if $userid !~ m/\@$realm$/;
			    # we save the old tokens 
			    $oldtokens->{$userid} = $oldusers->{$userid}->{tokens};
			    $oldenabled->{$userid} = $oldusers->{$userid}->{enable} // 0;
			    delete $oldusers->{$userid};
			    PVE::AccessControl::delete_user_acl($userid, $usercfg)
				if $param->{purge} && !$users->{$userid};
			    print "removed user '$userid'\n";
			}
		    }

		    foreach my $userid (keys %$users) {
			my $user = $users->{$userid};
			if (!defined($oldusers->{$userid})) {
			    $oldusers->{$userid} = $user;

			    if (defined($oldenabled->{$userid})) {
				$oldusers->{$userid}->{enable} = $oldenabled->{$userid};
			    } elsif ($param->{enable}) {
				$oldusers->{$userid}->{enable} = 1;
			    }

			    if (defined($oldtokens->{$userid})) {
				$oldusers->{$userid}->{tokens} = $oldtokens->{$userid};
			    }

			    print "added user '$userid'\n";
			} else {
			    my $olduser = $oldusers->{$userid};
			    foreach my $attr (keys %$user) {
				$olduser->{$attr} = $user->{$attr};
			    }
			    print "updated user '$userid'\n";
			}
		    }
		}

		if ($sync_groups) {
		    print "syncing groups\n";
		    my $oldgroups = $usercfg->{groups};

		    if ($param->{full}) {
			print "full sync, deleting existing groups first\n";
			foreach my $groupid (keys %$oldgroups) {
			    next if $groupid !~ m/\-$realm$/;
			    delete $oldgroups->{$groupid};
			    PVE::AccessControl::delete_group_acl($groupid, $usercfg)
				if $param->{purge} && !$groups->{$groupid};
			    print "removed group '$groupid'\n";
			}
		    }

		    foreach my $groupid (keys %$groups) {
			my $group = $groups->{$groupid};
			if (!defined($oldgroups->{$groupid})) {
			    $oldgroups->{$groupid} = $group;
			    print "added group '$groupid'\n";
			} else {
			    my $oldgroup = $oldgroups->{$groupid};
			    foreach my $attr (keys %$group) {
				$oldgroup->{$attr} = $group->{$attr};
			    }
			    print "updated group '$groupid'\n";
			}
		    }
		}

		cfs_write_file("user.cfg", $usercfg);
		print "successfully updated $whatstring configuration\n";
	    }, "syncing $whatstring failed");
	};

	return $rpcenv->fork_worker('ldapsync', $realm, $authuser, $worker);
    }});

1;

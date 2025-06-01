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

# maps old 'full'/'purge' parameters to new 'remove-vanished'
# TODO remove when we delete the 'full'/'purge' parameters
my $map_remove_vanished = sub {
    my ($opt, $delete_deprecated) = @_;

    if (!defined($opt->{'remove-vanished'}) && ($opt->{full} || $opt->{purge})) {
        my $props = [];
        push @$props, 'entry', 'properties' if $opt->{full};
        push @$props, 'acl' if $opt->{purge};
        $opt->{'remove-vanished'} = join(';', @$props);
    }

    if ($delete_deprecated) {
        delete $opt->{full};
        delete $opt->{purge};
    }

    return $opt;
};

my $map_sync_default_options = sub {
    my ($cfg, $delete_deprecated) = @_;

    my $opt = $cfg->{'sync-defaults-options'};
    return if !defined($opt);
    my $sync_opts_fmt = PVE::JSONSchema::get_format('realm-sync-options');

    my $old_opt = PVE::JSONSchema::parse_property_string($sync_opts_fmt, $opt);

    my $new_opt = $map_remove_vanished->($old_opt, $delete_deprecated);

    $cfg->{'sync-defaults-options'} =
        PVE::JSONSchema::print_property_string($new_opt, $sync_opts_fmt);
};

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Authentication domain index.",
    permissions => {
        description =>
            "Anyone can access that, because we need that list for the login box (before the user is authenticated).",
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
                    enum => ['yubico', 'oath'],
                    optional => 1,
                },
                comment => {
                    description =>
                        "A comment. The GUI use this text when you select a domain (Realm) on the login window.",
                    type => 'string',
                    optional => 1,
                },
            },
        },
        links => [{ rel => 'child', href => "{realm}" }],
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
    },
});

__PACKAGE__->register_method({
    name => 'create',
    protected => 1,
    path => '',
    method => 'POST',
    permissions => {
        check => ['perm', '/access/realm', ['Realm.Allocate']],
    },
    description => "Add an authentication server.",
    parameters => PVE::Auth::Plugin->createSchema(
        0,
        {
            'check-connection' => {
                description => 'Check bind connection to the server.',
                type => 'boolean',
                optional => 1,
                default => 0,
            },
        },
    ),
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
                my $check_connection = extract_param($param, 'check-connection');

                die "domain '$realm' already exists\n"
                    if $ids->{$realm};

                die "unable to use reserved name '$realm'\n"
                    if ($realm eq 'pam' || $realm eq 'pve');

                die "unable to create builtin type '$type'\n"
                    if ($type eq 'pam' || $type eq 'pve');

                die
                    "'check-connection' parameter can only be set for realms of type 'ldap' or 'ad'\n"
                    if defined($check_connection) && !($type eq 'ldap' || $type eq 'ad');

                if ($type eq 'ad' || $type eq 'ldap') {
                    $map_sync_default_options->($param, 1);
                }

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

                # Only for LDAP/AD, implied through the existence of the 'check-connection' param
                $plugin->check_connection($realm, $config, password => $password)
                    if $check_connection;

                cfs_write_file($domainconfigfile, $cfg);
            },
            "add auth server failed",
        );

        return undef;
    },
});

__PACKAGE__->register_method({
    name => 'update',
    path => '{realm}',
    method => 'PUT',
    permissions => {
        check => ['perm', '/access/realm', ['Realm.Allocate']],
    },
    description => "Update authentication server settings.",
    protected => 1,
    parameters => PVE::Auth::Plugin->updateSchema(
        0,
        {
            'check-connection' => {
                description => 'Check bind connection to the server.',
                type => 'boolean',
                optional => 1,
                default => 0,
            },
        },
    ),
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
                my $type = $ids->{$realm}->{type};
                my $check_connection = extract_param($param, 'check-connection');

                die "domain '$realm' does not exist\n"
                    if !$ids->{$realm};

                die
                    "'check-connection' parameter can only be set for realms of type 'ldap' or 'ad'\n"
                    if defined($check_connection) && !($type eq 'ldap' || $type eq 'ad');

                my $delete_str = extract_param($param, 'delete');
                die "no options specified\n"
                    if !$delete_str && !scalar(keys %$param) && !defined($password);

                my $delete_pw = 0;
                foreach my $opt (PVE::Tools::split_list($delete_str)) {
                    delete $ids->{$realm}->{$opt};
                    $delete_pw = 1 if $opt eq 'password';
                }

                if ($type eq 'ad' || $type eq 'ldap') {
                    $map_sync_default_options->($param, 1);
                }

                my $plugin = PVE::Auth::Plugin->lookup($type);
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

                # Only for LDAP/AD, implied through the existence of the 'check-connection' param
                $plugin->check_connection($realm, $ids->{$realm}, password => $password)
                    if $check_connection;

                cfs_write_file($domainconfigfile, $cfg);
            },
            "update auth server failed",
        );

        return undef;
    },
});

# fixme: return format!
__PACKAGE__->register_method({
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
            realm => get_standard_option('realm'),
        },
    },
    returns => {},
    code => sub {
        my ($param) = @_;

        my $cfg = cfs_read_file($domainconfigfile);

        my $realm = $param->{realm};

        my $data = $cfg->{ids}->{$realm};
        die "domain '$realm' does not exist\n" if !$data;

        my $type = $data->{type};
        if ($type eq 'ad' || $type eq 'ldap') {
            $map_sync_default_options->($data);
        }

        $data->{digest} = $cfg->{digest};

        return $data;
    },
});

__PACKAGE__->register_method({
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
            realm => get_standard_option('realm'),
        },
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
            },
            "delete auth server failed",
        );

        return undef;
    },
});

my $update_users = sub {
    my ($usercfg, $realm, $synced_users, $opts) = @_;

    if (defined(my $vanished = $opts->{'remove-vanished'})) {
        print "syncing users (remove-vanished opts: $vanished)\n";
    } else {
        print "syncing users\n";
    }

    $usercfg->{users} = {} if !defined($usercfg->{users});
    my $users = $usercfg->{users};
    my $to_remove = { map { $_ => 1 } split(';', $opts->{'remove-vanished'} // '') };

    print "deleting outdated existing users first\n" if $to_remove->{entry};
    foreach my $userid (sort keys %$users) {
        next if $userid !~ m/\@$realm$/;
        next if defined($synced_users->{$userid});

        if ($to_remove->{entry}) {
            print "remove user '$userid'\n";
            delete $users->{$userid};
        }

        if ($to_remove->{acl}) {
            print "purge users '$userid' ACL entries\n";
            PVE::AccessControl::delete_user_acl($userid, $usercfg);
        }
    }

    foreach my $userid (sort keys %$synced_users) {
        my $synced_user = $synced_users->{$userid} // {};
        my $olduser = $users->{$userid};
        if ($to_remove->{properties} || !defined($olduser)) {
            # we use the synced user, but want to keep some properties on update
            if (defined($olduser)) {
                print "overwriting user '$userid'\n";
            } else {
                $olduser = {};
                print "adding user '$userid'\n";
            }
            my $user = $users->{$userid} = $synced_user;

            my $enabled = $olduser->{enable} // $opts->{'enable-new'};
            $user->{enable} = $enabled if defined($enabled);
            $user->{tokens} = $olduser->{tokens} if defined($olduser->{tokens});

        } else {
            foreach my $attr (keys %$synced_user) {
                $olduser->{$attr} = $synced_user->{$attr};
            }
            print "updating user '$userid'\n";
        }
    }
};

my $update_groups = sub {
    my ($usercfg, $realm, $synced_groups, $opts) = @_;

    if (defined(my $vanished = $opts->{'remove-vanished'})) {
        print "syncing groups (remove-vanished opts: $vanished)\n";
    } else {
        print "syncing groups\n";
    }

    $usercfg->{groups} = {} if !defined($usercfg->{groups});
    my $groups = $usercfg->{groups};
    my $to_remove = { map { $_ => 1 } split(';', $opts->{'remove-vanished'} // '') };

    print "deleting outdated existing groups first\n" if $to_remove->{entry};
    foreach my $groupid (sort keys %$groups) {
        next if $groupid !~ m/\-$realm$/;
        next if defined($synced_groups->{$groupid});

        if ($to_remove->{entry}) {
            print "remove group '$groupid'\n";
            delete $groups->{$groupid};
        }

        if ($to_remove->{acl}) {
            print "purge groups '$groupid' ACL entries\n";
            PVE::AccessControl::delete_group_acl($groupid, $usercfg);
        }
    }

    foreach my $groupid (sort keys %$synced_groups) {
        my $synced_group = $synced_groups->{$groupid};
        my $oldgroup = $groups->{$groupid};
        if ($to_remove->{properties} || !defined($oldgroup)) {
            if (defined($oldgroup)) {
                print "overwriting group '$groupid'\n";
            } else {
                print "adding group '$groupid'\n";
            }
            $groups->{$groupid} = $synced_group;
        } else {
            foreach my $attr (keys %$synced_group) {
                $oldgroup->{$attr} = $synced_group->{$attr};
            }
            print "updating group '$groupid'\n";
        }
    }
};

my $parse_sync_opts = sub {
    my ($param, $realmconfig) = @_;

    my $sync_opts_fmt = PVE::JSONSchema::get_format('realm-sync-options');

    my $cfg_defaults = {};
    if (defined(my $cfg_opts = $realmconfig->{'sync-defaults-options'})) {
        $cfg_defaults = PVE::JSONSchema::parse_property_string($sync_opts_fmt, $cfg_opts);
    }

    my $res = {};
    for my $opt (sort keys %$sync_opts_fmt) {
        my $fmt = $sync_opts_fmt->{$opt};

        $res->{$opt} = $param->{$opt} // $cfg_defaults->{$opt} // $fmt->{default};
    }

    $map_remove_vanished->($res, 1);

    # only scope has no implicit value
    raise_param_exc({
        "scope" => 'Not passed as parameter and not defined in realm default sync options.',
    })
        if !defined($res->{scope});

    return $res;
};

__PACKAGE__->register_method({
    name => 'sync',
    path => '{realm}/sync',
    method => 'POST',
    permissions => {
        description => "'Realm.AllocateUser' on '/access/realm/<realm>' and "
            . " 'User.Modify' permissions to '/access/groups/'.",
        check => [
            'and',
            ['perm', '/access/realm/{realm}', ['Realm.AllocateUser']],
            ['perm', '/access/groups', ['User.Modify']],
        ],
    },
    description => "Syncs users and/or groups from the configured LDAP to user.cfg."
        . " NOTE: Synced groups will have the name 'name-\$realm', so make sure"
        . " those groups do not exist to prevent overwriting.",
    protected => 1,
    parameters => {
        additionalProperties => 0,
        properties => get_standard_option(
            'realm-sync-options',
            {
                realm => get_standard_option('realm'),
                'dry-run' => {
                    description => "If set, does not write anything.",
                    type => 'boolean',
                    optional => 1,
                    default => 0,
                },
            },
        ),
    },
    returns => {
        description => 'Worker Task-UPID',
        type => 'string',
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my $dry_run = extract_param($param, 'dry-run');
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
            print "(dry test run) " if $dry_run;
            print "starting sync for realm $realm\n";

            my ($synced_users, $dnmap) = $plugin->get_users($realmconfig, $realm);
            my $synced_groups = {};
            if ($scope eq 'groups' || $scope eq 'both') {
                $synced_groups = $plugin->get_groups($realmconfig, $realm, $dnmap);
            }

            PVE::AccessControl::lock_user_config(
                sub {
                    my $usercfg = cfs_read_file("user.cfg");
                    print "got data from server, updating $whatstring\n";

                    if ($scope eq 'users' || $scope eq 'both') {
                        $update_users->($usercfg, $realm, $synced_users, $opts);
                    }

                    if ($scope eq 'groups' || $scope eq 'both') {
                        $update_groups->($usercfg, $realm, $synced_groups, $opts);
                    }

                    if ($dry_run) {
                        print
                            "\nNOTE: Dry test run, changes were NOT written to the configuration.\n";
                        return;
                    }
                    cfs_write_file("user.cfg", $usercfg);
                    print "successfully updated $whatstring configuration\n";
                },
                "syncing $whatstring failed",
            );
        };

        my $workerid = !$dry_run ? 'auth-realm-sync' : 'auth-realm-sync-test';
        return $rpcenv->fork_worker($workerid, $realm, $authuser, $worker);
    },
});

1;

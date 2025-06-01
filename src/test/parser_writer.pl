#!/usr/bin/perl -w

use strict;
use warnings;

use Storable qw(dclone);
use Test::More;

use PVE::AccessControl;

PVE::AccessControl::create_roles();
my $default_user_cfg = {};
PVE::AccessControl::userconfig_force_defaults($default_user_cfg);

my $add_default_user_properties = sub {
    my ($user) = @_;

    $user->{enable} = 1 if !defined($user->{enable});
    $user->{expire} = 0 if !defined($user->{expire});
    $user->{email} = undef if !defined($user->{email});

    return $user;
};

sub default_roles {
    my $roles = dclone($default_user_cfg->{roles});
    return $roles;
}

sub default_roles_with {
    my ($extra_roles) = @_;

    my $roles = default_roles();

    foreach my $r (@$extra_roles) {
        my $role = dclone($r);
        my $roleid = delete $role->{id};
        $roles->{$roleid} = $role;
    }

    return $roles;
}

sub default_users {
    my $users = dclone($default_user_cfg->{users});
    return { map { $_ => $add_default_user_properties->($users->{$_}); } keys %$users };
}

sub default_users_with {
    my ($extra_users) = @_;

    my $users = default_users();

    foreach my $u (@$extra_users) {
        my $user = dclone($u);
        my $userid = delete $user->{id};
        $users->{$userid} = $add_default_user_properties->($user);
    }

    return $users;
}

sub default_groups {
    return {};
}

sub default_groups_with {
    my ($extra_groups) = @_;

    my $groups = default_groups();

    foreach my $g (@$extra_groups) {
        my $group = dclone($g);
        my $groupid = delete $group->{id};
        $groups->{$groupid} = $group;
    }

    return $groups;
}

sub default_pools {
    return {};
}

sub default_pools_with {
    my ($extra_pools) = @_;

    my $pools = default_pools();

    foreach my $p (@$extra_pools) {
        my $pool = dclone($p);
        my $poolid = delete $pool->{id};
        $pools->{$poolid} = $pool;
    }

    return $pools;
}

sub default_pool_vms_with {
    my ($extra_pools) = @_;

    my $vms = {};
    foreach my $pool (@$extra_pools) {
        foreach my $vmid (keys %{ $pool->{vms} }) {
            $vms->{$vmid} = $pool->{id};
        }
    }
    return $vms;
}

sub default_acls {
    return {};
}

# note: does not support merging paths!
sub default_acls_with {
    my ($extra_acls) = @_;

    my $acls = default_acls();

    foreach my $a (@$extra_acls) {
        my $acl = dclone($a);
        my $path = delete $acl->{path};
        my $split_path = [split("/", $path)];
        my $node = $acls;
        for my $p (@$split_path) {
            next if !$p;
            $node->{children} = {} if !$node->{children};
            $node->{children}->{$p} = {} if !$node->{children}->{$p};
            $node = $node->{children}->{$p};
        }
        %$node = (%$acl);
    }

    return $acls;
}

my $default_cfg = {
    test_pam => {
        'id' => 'test@pam',
        'enable' => 1,
        'expire' => 0,
        'email' => undef,
    },
    test2_pam => {
        'id' => 'test2@pam',
        'enable' => 1,
        'expire' => 0,
        'email' => undef,
    },
    test_pam_with_group => {
        'id' => 'test@pam',
        'enable' => 1,
        'expire' => 0,
        'email' => undef,
        'groups' => { 'testgroup' => 1 },
    },
    test2_pam_with_group => {
        'id' => 'test2@pam',
        'enable' => 1,
        'expire' => 0,
        'email' => undef,
        'groups' => { 'testgroup' => 1 },
    },
    test3_pam => {
        'id' => 'test3@pam',
        'enable' => 1,
        'expire' => 0,
        'email' => undef,
        'groups' => { 'another' => 1 },
    },
    test_pam_with_token => {
        'id' => 'test@pam',
        'enable' => 1,
        'expire' => 0,
        'email' => undef,
        'tokens' => {
            'full' => {
                'privsep' => 0,
                'expire' => 0,
            },
        },
    },
    test_pam2_with_token => {
        'id' => 'test2@pam',
        'enable' => 1,
        'expire' => 0,
        'email' => undef,
        'tokens' => {
            'full' => {
                'privsep' => 0,
                'expire' => 0,
            },
            'privsep' => {
                'privsep' => 1,
                'expire' => 0,
            },
            'expired' => {
                'privsep' => 0,
                'expire' => 1,
            },
        },
    },
    test_group_empty => {
        'id' => 'testgroup',
        users => {},
    },
    test_group_single_member => {
        'id' => 'testgroup',
        'users' => {
            'test@pam' => 1,
        },
    },
    test_group_members => {
        'id' => 'testgroup',
        'users' => {
            'test@pam' => 1,
            'test2@pam' => 1,
        },
    },
    test_group_second => {
        'id' => 'another',
        users => {
            'test3@pam' => 1,
        },
    },
    test_role_single_priv => {
        'id' => 'testrolesingle',
        'VM.Allocate' => 1,
    },
    test_role_privs => {
        'id' => 'testrole',
        'VM.Allocate' => 1,
        'Datastore.Audit' => 1,
    },
    test_pool_empty => {
        'id' => 'testpool',
        vms => {},
        storage => {},
        pools => {},
    },
    test_pool_members => {
        'id' => 'testpool',
        vms => { 123 => 1, 1234 => 1 },
        storage => { 'local' => 1, 'local-zfs' => 1 },
        pools => {},
    },
    test_pool_duplicate_vms => {
        'id' => 'test_duplicate_vms',
        vms => {},
        storage => {},
        pools => {},
    },
    test_pool_duplicate_storages => {
        'id' => 'test_duplicate_storages',
        vms => {},
        storage => { 'local' => 1, 'local-zfs' => 1 },
        pools => {},
    },
    acl_simple_user => {
        'path' => '/',
        users => {
            'test@pam' => {
                'PVEVMAdmin' => 1,
            },
        },
    },
    acl_complex_users => {
        'path' => '/storage',
        users => {
            'test2@pam' => {
                'PVEDatastoreUser' => 1,
            },
            'test@pam' => {
                'PVEDatastoreAdmin' => 1,
            },
        },
    },
    acl_complex_missing_user => {
        'path' => '/storage',
        users => {
            'test2@pam' => {
                'PVEDatastoreUser' => 1,
            },
            'test@pam' => {
                'PVEDatastoreAdmin' => 1,
            },
        },
    },
    acl_simple_token => {
        'path' => '/',
        tokens => {
            'test@pam!full' => {
                'PVEVMAdmin' => 1,
            },
        },
    },
    acl_complex_tokens => {
        'path' => '/storage',
        tokens => {
            'test2@pam!privsep' => {
                'PVEDatastoreUser' => 1,
            },
            'test2@pam!expired' => {
                'PVEDatastoreAdmin' => 1,
            },
            'test@pam!full' => {
                'PVEDatastoreAdmin' => 1,
            },
        },
    },
    acl_complex_missing_token => {
        'path' => '/storage',
        tokens => {
            'test2@pam!expired' => {
                'PVEDatastoreAdmin' => 1,
            },
            'test2@pam!privsep' => {
                'PVEDatastoreUser' => 1,
            },
        },
    },
    acl_simple_group => {
        'path' => '/',
        groups => {
            'testgroup' => {
                'PVEVMAdmin' => 1,
            },
        },
    },
    acl_complex_groups => {
        'path' => '/storage',
        groups => {
            'testgroup' => {
                'PVEDatastoreAdmin' => 1,
            },
            'another' => {
                'PVEDatastoreUser' => 1,
            },
        },
    },
    acl_simple_group_noprop => {
        'path' => '/',
        groups => {
            'testgroup' => {
                'PVEVMAdmin' => 0,
            },
        },
    },
    acl_complex_groups_noprop => {
        'path' => '/storage',
        groups => {
            'testgroup' => {
                'PVEDatastoreAdmin' => 0,
            },
            'another' => {
                'PVEDatastoreUser' => 0,
            },
        },
    },
    acl_complex_missing_group => {
        'path' => '/storage',
        groups => {
            'testgroup' => {
                'PVEDatastoreAdmin' => 1,
            },
            'another' => {
                'PVEDatastoreUser' => 1,
            },
        },
    },
    acl_missing_role => {
        'path' => '/storage',
        users => {
            'test@pam' => {
                'MissingRole' => 1,
            },
        },
    },
};

$default_cfg->{'acl_complex_mixed_root'} = {
    'path' => '/',
    users => $default_cfg->{'acl_simple_user'}->{users},
    groups => $default_cfg->{'acl_simple_group'}->{groups},
};

$default_cfg->{'acl_complex_mixed_storage'} = {
    'path' => '/storage',
    users => $default_cfg->{'acl_complex_users'}->{users},
    groups => $default_cfg->{'acl_complex_groups'}->{groups},
};

$default_cfg->{'acl_complex_mixed_root_noprop'} = {
    'path' => '/',
    users => $default_cfg->{'acl_simple_user'}->{users},
    groups => $default_cfg->{'acl_simple_group_noprop'}->{groups},
};

$default_cfg->{'acl_complex_mixed_storage_noprop'} = {
    'path' => '/storage',
    users => $default_cfg->{'acl_complex_users'}->{users},
    groups => $default_cfg->{'acl_complex_groups_noprop'}->{groups},
};

my $default_raw = {
    users => {
        'root@pam' => 'user:root@pam:1:0::::::',
        'test_pam' => 'user:test@pam:1:0::::::',
        'test2_pam' => 'user:test2@pam:1:0::::::',
        'test3_pam' => 'user:test3@pam:1:0::::::',
    },
    groups => {
        'test_group_empty' => 'group:testgroup:::',
        'test_group_single_member' => 'group:testgroup:test@pam::',
        'test_group_members' => 'group:testgroup:test2@pam,test@pam::',
        'test_group_members_out_of_order' => 'group:testgroup:test@pam,test2@pam::',
        'test_group_second' => 'group:another:test3@pam::',
    },
    tokens => {
        'test_token_simple' => 'token:test@pam!full:0:0::',
        'test_token_multi_full' => 'token:test2@pam!full:0:0::',
        'test_token_multi_privsep' => 'token:test2@pam!privsep:0:1::',
        'test_token_multi_expired' => 'token:test2@pam!expired:1:0::',
    },
    roles => {
        'test_role_single_priv' => 'role:testrolesingle:VM.Allocate:',
        'test_role_privs' => 'role:testrole:Datastore.Audit,VM.Allocate:',
        'test_role_privs_out_of_order' => 'role:testrole:VM.Allocate,Datastore.Audit:',
        'test_role_privs_duplicate' => 'role:testrole:VM.Allocate,Datastore.Audit,VM.Allocate:',
        'test_role_privs_invalid' => 'role:testrole:VM.Invalid,Datastore.Audit,VM.Allocate:',
    },
    pools => {
        'test_pool_empty' => 'pool:testpool::::',
        'test_pool_invalid' => 'pool:testpool::non-numeric:inval!d:',
        'test_pool_members' => 'pool:testpool::123,1234:local,local-zfs:',
        'test_pool_duplicate_vms' => 'pool:test_duplicate_vms::123,1234::',
        'test_pool_duplicate_vms_expected' => 'pool:test_duplicate_vms::::',
        'test_pool_duplicate_storages' => 'pool:test_duplicate_storages:::local,local-zfs:',
    },
    acl => {
        'acl_simple_user' => 'acl:1:/:test@pam:PVEVMAdmin:',
        'acl_complex_users_1' => 'acl:1:/storage:test@pam:PVEDatastoreAdmin:',
        'acl_complex_users_2' => 'acl:1:/storage:test2@pam:PVEDatastoreUser:',
        'acl_simple_token' => 'acl:1:/:test@pam!full:PVEVMAdmin:',
        'acl_complex_tokens_1' =>
            'acl:1:/storage:test2@pam!expired,test@pam!full:PVEDatastoreAdmin:',
        'acl_complex_tokens_2' => 'acl:1:/storage:test2@pam!privsep:PVEDatastoreUser:',
        'acl_complex_tokens_1_missing' => 'acl:1:/storage:test2@pam!expired:PVEDatastoreAdmin:',
        'acl_simple_group' => 'acl:1:/:@testgroup:PVEVMAdmin:',
        'acl_complex_groups_1' => 'acl:1:/storage:@testgroup:PVEDatastoreAdmin:',
        'acl_complex_groups_2' => 'acl:1:/storage:@another:PVEDatastoreUser:',
        'acl_simple_group_noprop' => 'acl:0:/:@testgroup:PVEVMAdmin:',
        'acl_complex_groups_1_noprop' => 'acl:0:/storage:@testgroup:PVEDatastoreAdmin:',
        'acl_complex_groups_2_noprop' => 'acl:0:/storage:@another:PVEDatastoreUser:',
        'acl_complex_mixed_1' => 'acl:1:/:@testgroup,test@pam:PVEVMAdmin:',
        'acl_complex_mixed_2' => 'acl:1:/storage:@testgroup,test@pam:PVEDatastoreAdmin:',
        'acl_complex_mixed_3' => 'acl:1:/storage:@another,test2@pam:PVEDatastoreUser:',
        'acl_missing_role' => 'acl:1:/storage:test@pam:MissingRole:',
    },
};

my $tests = [
    {
        name => "empty_config",
        config => {},
        expected_config => {
            acl_root => default_acls(),
            users => { 'root@pam' => { enable => 1 } },
            roles => default_roles(),
        },
        raw => "",
        expected_raw => "\n\n\n\n",
    },
    {
        name => "default_config",
        config => {
            acl_root => default_acls(),
            users => default_users(),
            roles => default_roles(),
        },
        raw => $default_raw->{users}->{'root@pam'} . "\n\n\n\n\n",
    },
    {
        name => "group_empty",
        config => {
            acl_root => default_acls(),
            users => default_users(),
            roles => default_roles(),
            groups => default_groups_with([$default_cfg->{'test_group_empty'}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_empty'} . "\n\n" . "\n\n",
    },
    {
        name => "group_inexisting_member",
        config => {
            acl_root => default_acls(),
            users => default_users(),
            roles => default_roles(),
            groups => default_groups_with([$default_cfg->{'test_group_empty'}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n\n"
            . "group:testgroup:does_not_exist::"
            . "\n\n\n\n",
        expected_raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_empty'} . "\n\n" . "\n\n",
    },
    {
        name => "group_invalid_member",
        expected_config => {
            acl_root => default_acls(),
            users => default_users(),
            roles => default_roles(),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n\n"
            . 'group:inval!d:root@pam:' . "\n\n",
    },
    {
        name => "group_with_one_member",
        config => {
            acl_root => default_acls(),
            users => default_users_with([$default_cfg->{test_pam_with_group}]),
            roles => default_roles(),
            groups => default_groups_with([$default_cfg->{'test_group_single_member'}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_single_member'} . "\n\n" . "\n\n",
    },
    {
        name => "group_with_members",
        config => {
            acl_root => default_acls(),
            users => default_users_with(
                [$default_cfg->{test_pam_with_group}, $default_cfg->{test2_pam_with_group}]
            ),
            roles => default_roles(),
            groups => default_groups_with([$default_cfg->{'test_group_members'}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_members'} . "\n\n" . "\n\n",
    },
    {
        name => "token_simple",
        config => {
            acl_root => default_acls(),
            users => default_users_with([$default_cfg->{test_pam_with_token}]),
            roles => default_roles(),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n"
            . $default_raw->{tokens}->{'test_token_simple'}
            . "\n\n\n\n\n",
    },
    {
        name => "token_multi",
        config => {
            acl_root => default_acls(),
            users => default_users_with(
                [$default_cfg->{test_pam_with_token}, $default_cfg->{test_pam2_with_token}]
            ),
            roles => default_roles(),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{tokens}->{'test_token_multi_expired'} . "\n"
            . $default_raw->{tokens}->{'test_token_multi_full'} . "\n"
            . $default_raw->{tokens}->{'test_token_multi_privsep'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n"
            . $default_raw->{tokens}->{'test_token_simple'} . "\n"
            . "\n\n\n\n",
    },
    {
        name => "custom_role_with_single_priv",
        config => {
            acl_root => default_acls(),
            users => default_users(),
            roles => default_roles_with([$default_cfg->{test_role_single_priv}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n\n"
            . $default_raw->{roles}->{'test_role_single_priv'} . "\n\n",
    },
    {
        name => "custom_role_with_privs",
        config => {
            acl_root => default_acls(),
            users => default_users(),
            roles => default_roles_with([$default_cfg->{test_role_privs}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n\n"
            . $default_raw->{roles}->{'test_role_privs'} . "\n\n",
    },
    {
        name => "custom_role_with_duplicate_privs",
        config => {
            acl_root => default_acls(),
            users => default_users(),
            roles => default_roles_with([$default_cfg->{test_role_privs}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n\n"
            . $default_raw->{roles}->{'test_role_privs_duplicate'} . "\n\n",
        expected_raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n\n"
            . $default_raw->{roles}->{'test_role_privs'} . "\n\n",
    },
    {
        name => "custom_role_with_invalid_priv",
        config => {
            acl_root => default_acls(),
            users => default_users(),
            roles => default_roles_with([$default_cfg->{test_role_privs}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n\n"
            . $default_raw->{roles}->{'test_role_privs_invalid'} . "\n\n",
        expected_raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n\n"
            . $default_raw->{roles}->{'test_role_privs'} . "\n\n",
    },
    {
        name => "pool_empty",
        config => {
            acl_root => default_acls(),
            users => default_users(),
            roles => default_roles(),
            pools => default_pools_with([$default_cfg->{test_pool_empty}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n"
            . $default_raw->{pools}->{'test_pool_empty'}
            . "\n\n\n",
    },
    {
        name => "pool_invalid",
        config => {
            acl_root => default_acls(),
            users => default_users(),
            roles => default_roles(),
            pools => default_pools_with([$default_cfg->{test_pool_empty}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n"
            . $default_raw->{pools}->{'test_pool_invalid'}
            . "\n\n\n",
        expected_raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n"
            . $default_raw->{pools}->{'test_pool_empty'}
            . "\n\n\n",
    },
    {
        name => "pool_members",
        config => {
            acl_root => default_acls(),
            users => default_users(),
            roles => default_roles(),
            pools => default_pools_with([$default_cfg->{test_pool_members}]),
            vms => default_pool_vms_with([$default_cfg->{test_pool_members}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n"
            . $default_raw->{pools}->{'test_pool_members'}
            . "\n\n\n",
    },
    {
        name => "pool_duplicate_members",
        config => {
            acl_root => default_acls(),
            users => default_users(),
            roles => default_roles(),
            pools => default_pools_with(
                [
                    $default_cfg->{test_pool_members},
                    $default_cfg->{test_pool_duplicate_vms},
                    $default_cfg->{test_pool_duplicate_storages},
                ],
            ),
            vms => default_pool_vms_with([$default_cfg->{test_pool_members}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n"
            . $default_raw->{pools}->{'test_pool_members'} . "\n"
            . $default_raw->{pools}->{'test_pool_duplicate_vms'} . "\n"
            . $default_raw->{pools}->{'test_pool_duplicate_storages'} . "\n",
        expected_raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n"
            . $default_raw->{pools}->{'test_pool_duplicate_storages'} . "\n"
            . $default_raw->{pools}->{'test_pool_duplicate_vms_expected'} . "\n"
            . $default_raw->{pools}->{'test_pool_members'}
            . "\n\n\n",
    },
    {
        name => "acl_simple_user",
        config => {
            users => default_users_with([$default_cfg->{test_pam}]),
            roles => default_roles(),
            acl_root => default_acls_with([$default_cfg->{acl_simple_user}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test_pam'}
            . "\n\n\n\n\n"
            . $default_raw->{acl}->{'acl_simple_user'} . "\n",
    },
    {
        name => "acl_complex_users",
        config => {
            users =>
                default_users_with([$default_cfg->{test_pam}, $default_cfg->{'test2_pam'}]),
            roles => default_roles(),
            acl_root => default_acls_with(
                [$default_cfg->{acl_simple_user}, $default_cfg->{acl_complex_users}]
            ),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{users}->{'test_pam'}
            . "\n\n\n\n\n"
            . $default_raw->{acl}->{'acl_simple_user'} . "\n"
            . $default_raw->{acl}->{'acl_complex_users_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_users_2'} . "\n",
    },
    {
        name => "acl_complex_missing_user",
        config => {
            users => default_users_with([$default_cfg->{test2_pam}]),
            roles => default_roles(),
            acl_root => default_acls_with(
                [$default_cfg->{acl_simple_user}, $default_cfg->{acl_complex_missing_user}]
            ),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'}
            . "\n\n\n\n\n"
            . $default_raw->{acl}->{'acl_simple_user'} . "\n"
            . $default_raw->{acl}->{'acl_complex_users_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_users_2'} . "\n",
    },
    {
        name => "acl_simple_group",
        config => {
            users => default_users_with([$default_cfg->{test_pam_with_group}]),
            groups => default_groups_with([$default_cfg->{'test_group_single_member'}]),
            roles => default_roles(),
            acl_root => default_acls_with([$default_cfg->{acl_simple_group}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_single_member'}
            . "\n\n\n\n"
            . $default_raw->{acl}->{'acl_simple_group'} . "\n",
    },
    {
        name => "acl_complex_groups",
        config => {
            users => default_users_with(
                [
                    $default_cfg->{test_pam_with_group},
                    $default_cfg->{'test2_pam_with_group'},
                    $default_cfg->{'test3_pam'},
                ],
            ),
            groups => default_groups_with(
                [$default_cfg->{'test_group_members'}, $default_cfg->{'test_group_second'}]
            ),
            roles => default_roles(),
            acl_root => default_acls_with(
                [$default_cfg->{acl_simple_group}, $default_cfg->{acl_complex_groups}]
            ),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{users}->{'test3_pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_second'} . "\n"
            . $default_raw->{groups}->{'test_group_members'}
            . "\n\n\n\n"
            . $default_raw->{acl}->{'acl_simple_group'} . "\n"
            . $default_raw->{acl}->{'acl_complex_groups_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_groups_2'} . "\n",
    },
    {
        name => "acl_complex_missing_group",
        config => {
            users => default_users_with(
                [
                    $default_cfg->{test_pam},
                    $default_cfg->{'test2_pam'},
                    $default_cfg->{'test3_pam'},
                ],
            ),
            groups => default_groups_with([$default_cfg->{'test_group_second'}]),
            roles => default_roles(),
            acl_root => default_acls_with(
                [$default_cfg->{acl_simple_group}, $default_cfg->{acl_complex_missing_group}]
            ),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{users}->{'test3_pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_second'} . "\n"
            . $default_raw->{acl}->{'acl_simple_group'} . "\n"
            . $default_raw->{acl}->{'acl_complex_groups_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_groups_2'} . "\n",
        expected_raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{users}->{'test3_pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_second'}
            . "\n\n\n\n"
            . $default_raw->{acl}->{'acl_simple_group'} . "\n"
            . $default_raw->{acl}->{'acl_complex_groups_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_groups_2'} . "\n",
    },
    {
        name => "acl_simple_token",
        config => {
            users => default_users_with([$default_cfg->{test_pam_with_token}]),
            roles => default_roles(),
            acl_root => default_acls_with([$default_cfg->{acl_simple_token}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n"
            . $default_raw->{tokens}->{'test_token_simple'}
            . "\n\n\n\n\n"
            . $default_raw->{acl}->{'acl_simple_token'} . "\n",
    },
    {
        name => "acl_complex_tokens",
        config => {
            users => default_users_with(
                [$default_cfg->{test_pam_with_token}, $default_cfg->{'test_pam2_with_token'}]
            ),
            roles => default_roles(),
            acl_root => default_acls_with(
                [$default_cfg->{acl_simple_token}, $default_cfg->{acl_complex_tokens}]
            ),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{tokens}->{'test_token_multi_expired'} . "\n"
            . $default_raw->{tokens}->{'test_token_multi_full'} . "\n"
            . $default_raw->{tokens}->{'test_token_multi_privsep'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n"
            . $default_raw->{tokens}->{'test_token_simple'}
            . "\n\n\n\n\n"
            . $default_raw->{acl}->{'acl_simple_token'} . "\n"
            . $default_raw->{acl}->{'acl_complex_tokens_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_tokens_2'} . "\n",
    },
    {
        name => "acl_complex_missing_token",
        config => {
            users => default_users_with(
                [$default_cfg->{test_pam}, $default_cfg->{test_pam2_with_token}]
            ),
            roles => default_roles(),
            acl_root => default_acls_with([$default_cfg->{acl_complex_missing_token}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{tokens}->{'test_token_multi_expired'} . "\n"
            . $default_raw->{tokens}->{'test_token_multi_full'} . "\n"
            . $default_raw->{tokens}->{'test_token_multi_privsep'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n"
            . $default_raw->{acl}->{'acl_simple_token'} . "\n"
            . $default_raw->{acl}->{'acl_complex_tokens_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_tokens_2'} . "\n",
        expected_raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{tokens}->{'test_token_multi_expired'} . "\n"
            . $default_raw->{tokens}->{'test_token_multi_full'} . "\n"
            . $default_raw->{tokens}->{'test_token_multi_privsep'} . "\n"
            . $default_raw->{users}->{'test_pam'}
            . "\n\n\n\n\n"
            . $default_raw->{acl}->{'acl_complex_tokens_1_missing'} . "\n"
            . $default_raw->{acl}->{'acl_complex_tokens_2'} . "\n",
    },
    {
        name => "acl_missing_role",
        config => {
            users => default_users_with([$default_cfg->{test_pam}]),
            roles => default_roles(),
            acl_root => default_acls_with([$default_cfg->{acl_simple_user}]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test_pam'}
            . "\n\n\n\n\n"
            . $default_raw->{acl}->{'acl_simple_user'} . "\n"
            . $default_raw->{acl}->{'acl_missing_role'} . "\n",
        expected_raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test_pam'}
            . "\n\n\n\n\n"
            . $default_raw->{acl}->{'acl_simple_user'} . "\n",
    },
    {
        name => "acl_complex_mixed",
        config => {
            users => default_users_with(
                [
                    $default_cfg->{test_pam_with_group},
                    $default_cfg->{'test2_pam_with_group'},
                    $default_cfg->{'test3_pam'},
                ],
            ),
            groups => default_groups_with(
                [$default_cfg->{'test_group_members'}, $default_cfg->{'test_group_second'}]
            ),
            roles => default_roles(),
            acl_root => default_acls_with([
                $default_cfg->{acl_complex_mixed_root},
                $default_cfg->{acl_complex_mixed_storage},
            ]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{users}->{'test3_pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_second'} . "\n"
            . $default_raw->{groups}->{'test_group_members'}
            . "\n\n\n\n"
            . $default_raw->{acl}->{'acl_simple_group'} . "\n"
            . $default_raw->{acl}->{'acl_complex_groups_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_groups_2'} . "\n"
            . $default_raw->{acl}->{'acl_simple_user'} . "\n"
            . $default_raw->{acl}->{'acl_complex_users_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_users_2'} . "\n",
        expected_raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{users}->{'test3_pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_second'} . "\n"
            . $default_raw->{groups}->{'test_group_members'}
            . "\n\n\n\n"
            . $default_raw->{acl}->{'acl_complex_mixed_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_mixed_2'} . "\n"
            . $default_raw->{acl}->{'acl_complex_mixed_3'} . "\n",
    },
    {
        name => "acl_complex_mixed_prop_noprop_no_merge_sort_by_path",
        config => {
            users => default_users_with(
                [
                    $default_cfg->{test_pam_with_group},
                    $default_cfg->{'test2_pam_with_group'},
                    $default_cfg->{'test3_pam'},
                ],
            ),
            groups => default_groups_with(
                [$default_cfg->{'test_group_members'}, $default_cfg->{'test_group_second'}]
            ),
            roles => default_roles(),
            acl_root => default_acls_with([
                $default_cfg->{acl_complex_mixed_root_noprop},
                $default_cfg->{acl_complex_mixed_storage_noprop},
            ]),
        },
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{users}->{'test3_pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_second'} . "\n"
            . $default_raw->{groups}->{'test_group_members'}
            . "\n\n\n\n"
            . $default_raw->{acl}->{'acl_simple_group_noprop'} . "\n"
            . $default_raw->{acl}->{'acl_simple_user'} . "\n"
            . $default_raw->{acl}->{'acl_complex_groups_1_noprop'} . "\n"
            . $default_raw->{acl}->{'acl_complex_groups_2_noprop'} . "\n"
            . $default_raw->{acl}->{'acl_complex_users_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_users_2'} . "\n",
    },
    {
        name => "sort_roles_and_privs",
        raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{roles}->{'test_role_single_priv'} . "\n\n"
            . $default_raw->{roles}->{'test_role_privs_out_of_order'} . "\n\n",
        expected_raw => ""
            . $default_raw->{users}->{'root@pam'}
            . "\n\n\n\n"
            . $default_raw->{roles}->{'test_role_privs'} . "\n"
            . $default_raw->{roles}->{'test_role_single_priv'} . "\n\n",
    },
    {
        name => "sort_users_and_group_members",
        raw => ""
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_members_out_of_order'} . "\n\n" . "\n\n",
        expected_raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_members'} . "\n\n" . "\n\n",
    },
    {
        name => "sort_user_groups_and_acls",
        raw => ""
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{users}->{'test3_pam'} . "\n"
            . $default_raw->{groups}->{'test_group_members_out_of_order'}
            . "\n\n\n\n"
            . $default_raw->{groups}->{'test_group_second'} . "\n"
            . $default_raw->{acl}->{'acl_simple_user'} . "\n"
            . $default_raw->{acl}->{'acl_simple_group'} . "\n"
            . $default_raw->{acl}->{'acl_complex_users_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_users_2'} . "\n"
            . $default_raw->{acl}->{'acl_complex_groups_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_groups_2'} . "\n",
        expected_raw => ""
            . $default_raw->{users}->{'root@pam'} . "\n"
            . $default_raw->{users}->{'test2_pam'} . "\n"
            . $default_raw->{users}->{'test3_pam'} . "\n"
            . $default_raw->{users}->{'test_pam'} . "\n\n"
            . $default_raw->{groups}->{'test_group_second'} . "\n"
            . $default_raw->{groups}->{'test_group_members'}
            . "\n\n\n\n"
            . $default_raw->{acl}->{'acl_complex_mixed_1'} . "\n"
            . $default_raw->{acl}->{'acl_complex_mixed_2'} . "\n"
            . $default_raw->{acl}->{'acl_complex_mixed_3'} . "\n",
    },
    {
        name => 'default_values',
        config => {
            users => {
                'root@pam' => {
                    enable => 0,
                    expire => 0,
                    email => undef,
                },
                'test@pam' => {
                    enable => 0,
                    expire => 0,
                    email => undef,
                    tokens => {
                        'test' => {
                            expire => 0,
                            privsep => 0,
                        },
                    },
                },
            },
            roles => default_roles_with([{ id => 'testrole' }]),
            groups => default_groups_with([$default_cfg->{test_group_empty}]),
            pools => default_pools_with([$default_cfg->{test_pool_empty}]),
            acl_root => {},
        },
        raw => ""
            . 'user:root@pam' . "\n"
            . 'user:test@pam' . "\n"
            . 'token:test@pam!test' . "\n\n"
            . 'group:testgroup' . "\n\n"
            . 'pool:testpool' . "\n\n"
            . 'role:testrole' . "\n\n"
            . 'acl::/:',
        expected_raw => ""
            . 'user:root@pam:0:0::::::' . "\n"
            . 'user:test@pam:0:0::::::' . "\n"
            . 'token:test@pam!test:0:0::' . "\n\n"
            . 'group:testgroup:::' . "\n\n"
            . 'pool:testpool::::' . "\n\n"
            . 'role:testrole::' . "\n\n",
    },
];

my $number_of_tests_run = 0;
foreach my $t (@$tests) {
    my $expected_config = $t->{expected_config} // $t->{config};
    my $expected_raw = $t->{expected_raw} // $t->{raw};
    if (defined($t->{raw})) {
        my $parsed = PVE::AccessControl::parse_user_config($t->{name}, $t->{raw});
        if (defined($expected_config)) {
            is_deeply($parsed, $expected_config, "$t->{name}_parse");
            $number_of_tests_run++;
        }
        if (defined($t->{expected_raw}) && !defined($t->{config})) {
            is(
                PVE::AccessControl::write_user_config($t->{name}, $parsed),
                $t->{expected_raw},
                "$t->{name}_rewrite",
            );
            $number_of_tests_run++;
        }

    }
    if (defined($t->{config})) {
        my $written = PVE::AccessControl::write_user_config($t->{name}, $t->{config});
        if (defined($expected_raw)) {
            is($written, $expected_raw, "$t->{name}_write");
            $number_of_tests_run++;
        }
        if (defined($t->{expected_config}) && !defined($t->{raw})) {
            is_deeply(
                PVE::AccessControl::parse_user_config($t->{name}, $t->{written}),
                $t->{expected_config},
                "$t->{name}_reparse",
            );
            $number_of_tests_run++;
        }
    }
}

done_testing($number_of_tests_run);

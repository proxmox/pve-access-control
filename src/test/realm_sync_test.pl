#!/usr/bin/perl

use strict;
use warnings;

use Test::MockModule;
use Test::More;
use Storable qw(dclone);

use PVE::AccessControl;
use PVE::API2::Domains;

my $domainscfg = {
    ids => {
        "pam" => { type => 'pam' },
        "pve" => { type => 'pve' },
        "syncedrealm" => { type => 'ldap' },
    },
};

my $initialusercfg = {
    users => {
        'root@pam' => { username => 'root' },
        'user1@syncedrealm' => {
            username => 'user1',
            enable => 1,
            'keys' => 'some',
        },
        'user2@syncedrealm' => {
            username => 'user2',
            enable => 1,
        },
        'user3@syncedrealm' => {
            username => 'user3',
            enable => 1,
        },
    },
    groups => {
        'group1-syncedrealm' => { users => {} },
        'group2-syncedrealm' => { users => {} },
    },
    acl_root => {
        users => {
            'user3@syncedrealm' => {},
        },
        groups => {},
    },
};

my $sync_response = {
    user => [
        {
            attributes => { 'uid' => ['user1'] },
            dn => 'uid=user1,dc=syncedrealm',
        },
        {
            attributes => { 'uid' => ['user2'] },
            dn => 'uid=user2,dc=syncedrealm',
        },
        {
            attributes => { 'uid' => ['user4'] },
            dn => 'uid=user4,dc=syncedrealm',
        },
    ],
    groups => [
        {
            dn => 'dc=group1,dc=syncedrealm',
            members => [
                'uid=user1,dc=syncedrealm',
            ],
        },
        {
            dn => 'dc=group3,dc=syncedrealm',
            members => [
                'uid=nonexisting,dc=syncedrealm',
            ],
        },
    ],
};

my $returned_user_cfg = {};

# mocking all cluster and ldap operations
my $pve_cluster_module = Test::MockModule->new('PVE::Cluster');
$pve_cluster_module->mock(
    cfs_update => sub { },
    cfs_read_file => sub {
        my ($filename) = @_;
        if ($filename eq 'domains.cfg') { return dclone($domainscfg); }
        if ($filename eq 'user.cfg') { return dclone($initialusercfg); }
        die "unexpected cfs_read_file";
    },
    cfs_write_file => sub {
        my ($filename, $data) = @_;
        if ($filename eq 'user.cfg') {
            $returned_user_cfg = $data;
            return;
        }
        die "unexpected cfs_read_file";
    },
    cfs_lock_file => sub {
        my ($filename, $timeout, $code) = @_;
        return $code->();
    },
);

my $pve_api_domains = Test::MockModule->new('PVE::API2::Domains');
$pve_api_domains->mock(
    cfs_read_file => sub { PVE::Cluster::cfs_read_file(@_); },
    cfs_write_file => sub { PVE::Cluster::cfs_write_file(@_); },
);

my $pve_accesscontrol = Test::MockModule->new('PVE::AccessControl');
$pve_accesscontrol->mock(
    cfs_lock_file => sub { PVE::Cluster::cfs_lock_file(@_); },
);

my $pve_rpcenvironment = Test::MockModule->new('PVE::RPCEnvironment');
$pve_rpcenvironment->mock(
    get => sub { return bless {}, 'PVE::RPCEnvironment'; },
    get_user => sub { return 'root@pam'; },
    fork_worker => sub {
        my ($class, $workertype, $id, $user, $code) = @_;

        return $code->();
    },
);

my $pve_ldap_module = Test::MockModule->new('PVE::LDAP');
$pve_ldap_module->mock(
    ldap_connect => sub { return {}; },
    ldap_bind => sub { },
    query_users => sub {
        return $sync_response->{user};
    },
    query_groups => sub {
        return $sync_response->{groups};
    },
);

my $pve_auth_ldap = Test::MockModule->new('PVE::Auth::LDAP');
$pve_auth_ldap->mock(
    connect_and_bind => sub { return {}; },
);

my $tests = [
    [
        "non-full without purge",
        {
            realm => 'syncedrealm',
            scope => 'both',
        },
        {
            users => {
                'root@pam' => { username => 'root' },
                'user1@syncedrealm' => {
                    username => 'user1',
                    enable => 1,
                    'keys' => 'some',
                },
                'user2@syncedrealm' => {
                    username => 'user2',
                    enable => 1,
                },
                'user3@syncedrealm' => {
                    username => 'user3',
                    enable => 1,
                },
                'user4@syncedrealm' => {
                    username => 'user4',
                    enable => 1,
                },
            },
            groups => {
                'group1-syncedrealm' => {
                    users => {
                        'user1@syncedrealm' => 1,
                    },
                },
                'group2-syncedrealm' => { users => {} },
                'group3-syncedrealm' => { users => {} },
            },
            acl_root => {
                users => {
                    'user3@syncedrealm' => {},
                },
                groups => {},
            },
        },
    ],
    [
        "full without purge",
        {
            realm => 'syncedrealm',
            'remove-vanished' => 'entry;properties',
            scope => 'both',
        },
        {
            users => {
                'root@pam' => { username => 'root' },
                'user1@syncedrealm' => {
                    username => 'user1',
                    enable => 1,
                },
                'user2@syncedrealm' => {
                    username => 'user2',
                    enable => 1,
                },
                'user4@syncedrealm' => {
                    username => 'user4',
                    enable => 1,
                },
            },
            groups => {
                'group1-syncedrealm' => {
                    users => {
                        'user1@syncedrealm' => 1,
                    },
                },
                'group3-syncedrealm' => { users => {} },
            },
            acl_root => {
                users => {
                    'user3@syncedrealm' => {},
                },
                groups => {},
            },
        },
    ],
    [
        "non-full with purge",
        {
            realm => 'syncedrealm',
            'remove-vanished' => 'acl',
            scope => 'both',
        },
        {
            users => {
                'root@pam' => { username => 'root' },
                'user1@syncedrealm' => {
                    username => 'user1',
                    enable => 1,
                    'keys' => 'some',
                },
                'user2@syncedrealm' => {
                    username => 'user2',
                    enable => 1,
                },
                'user3@syncedrealm' => {
                    username => 'user3',
                    enable => 1,
                },
                'user4@syncedrealm' => {
                    username => 'user4',
                    enable => 1,
                },
            },
            groups => {
                'group1-syncedrealm' => {
                    users => {
                        'user1@syncedrealm' => 1,
                    },
                },
                'group2-syncedrealm' => { users => {} },
                'group3-syncedrealm' => { users => {} },
            },
            acl_root => {
                users => {},
                groups => {},
            },
        },
    ],
    [
        "full with purge",
        {
            realm => 'syncedrealm',
            'remove-vanished' => 'acl;entry;properties',
            scope => 'both',
        },
        {
            users => {
                'root@pam' => { username => 'root' },
                'user1@syncedrealm' => {
                    username => 'user1',
                    enable => 1,
                },
                'user2@syncedrealm' => {
                    username => 'user2',
                    enable => 1,
                },
                'user4@syncedrealm' => {
                    username => 'user4',
                    enable => 1,
                },
            },
            groups => {
                'group1-syncedrealm' => {
                    users => {
                        'user1@syncedrealm' => 1,
                    },
                },
                'group3-syncedrealm' => { users => {} },
            },
            acl_root => {
                users => {},
                groups => {},
            },
        },
    ],
    [
        "don't delete properties, but users and acls",
        {
            realm => 'syncedrealm',
            'remove-vanished' => 'acl;entry',
            scope => 'both',
        },
        {
            users => {
                'root@pam' => { username => 'root' },
                'user1@syncedrealm' => {
                    username => 'user1',
                    enable => 1,
                    'keys' => 'some',
                },
                'user2@syncedrealm' => {
                    username => 'user2',
                    enable => 1,
                },
                'user4@syncedrealm' => {
                    username => 'user4',
                    enable => 1,
                },
            },
            groups => {
                'group1-syncedrealm' => {
                    users => {
                        'user1@syncedrealm' => 1,
                    },
                },
                'group3-syncedrealm' => { users => {} },
            },
            acl_root => {
                users => {},
                groups => {},
            },
        },
    ],
];

for my $test (@$tests) {
    my $name = $test->[0];
    my $parameters = $test->[1];
    my $expected = $test->[2];
    $returned_user_cfg = {};
    PVE::API2::Domains->sync($parameters);
    is_deeply($returned_user_cfg, $expected, $name);
}

done_testing();

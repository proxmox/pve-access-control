#!/usr/bin/env perl

use v5.36;

use lib qw(..);

use Test::MockModule;
use Test::More;

use PVE::AccessControl;
use PVE::RPCEnvironment;
use PVE::Tools;

# test cases
my $tests = [
    {
        description => 'successful pruning of sdn resource acls',
        raw => <<~EOF,
        user:user1\@pve:1:0::::::
        user:user2\@pve:1:0::::::
        user:user3\@pve:1:0::::::
        role:SDNAdmin:SDN.Allocate,SDN.Audit
        role:SDNAudit:SDN.Audit
        acl:1:/sdn/zones/zone1:user3\@pve:SDNAdmin:
        acl:1:/sdn/zones/zone2:user3\@pve:SDNAdmin:
        acl:1:/sdn/zones/zone1/vnet1:user1\@pve:SDNAdmin:
        acl:1:/sdn/zones/zone1/vnet1/10:user1\@pve:SDNAdmin:
        acl:1:/sdn/zones/zone1/vnet2:user1\@pve:SDNAdmin:
        acl:1:/sdn/zones/zone1/vnet2/100:user1\@pve:SDNAudit:
        acl:1:/sdn/controllers/control:user2\@pve:SDNAdmin:
        acl:1:/sdn/prefix-lists/list:user2\@pve:SDNAdmin:
        acl:1:/sdn/route-maps/map:user2\@pve:SDNAdmin:
        acl:1:/sdn/fabrics/fabric:user2\@pve:SDNAdmin:
        EOF
        prune_paths => [
            'zones/zone2',
            'zones/zone1/vnet1',
            'zones/zone1/vnet2/100',
            'controllers/control',
            'prefix-lists/list',
            'route-maps/map',
            'fabrics/fabric',
        ],
        expected_roles => [
            # zone 1 remains, zone 2 is pruned
            ['user3@pve', '/sdn/zones/zone1', 'SDNAdmin'],
            ['user3@pve', '/sdn/zones/zone2', ''],

            # vnet1 is completely pruned
            ['user1@pve', '/sdn/zones/zone1/vnet1', ''],
            ['user1@pve', '/sdn/zones/zone1/vnet1/10', ''],

            # vnet2 remains, but the specific vnet2/100 override (SDNAudit) is removed,
            # so it falls back to inheriting SDNAdmin from vnet2
            ['user1@pve', '/sdn/zones/zone1/vnet2', 'SDNAdmin'],
            ['user1@pve', '/sdn/zones/zone1/vnet2/100', 'SDNAdmin'],

            # other SDN resources pruned
            ['user2@pve', '/sdn/controllers/control', ''],
            ['user2@pve', '/sdn/prefix-lists/list', ''],
            ['user2@pve', '/sdn/route-maps/map', ''],
            ['user2@pve', '/sdn/fabrics/fabric', ''],
        ],
    },
];

# mocking
my $cluster_module = Test::MockModule->new('PVE::Cluster');
$cluster_module->noop('cfs_update');

my $mocked_user_cfg_tree;
my $access_control_module = Test::MockModule->new('PVE::AccessControl');

$access_control_module->mock(
    'cfs_read_file' => sub {
        my ($filename) = @_;
        if ($filename eq 'user.cfg') {
            return $mocked_user_cfg_tree;
        }
        die "mock cfs_read_file: unexpected file $filename";
    },
    'cfs_write_file' => sub {
        my ($filename, $cfg) = @_;
        if ($filename eq 'user.cfg') {
            $mocked_user_cfg_tree = $cfg;
        }
    },
    'lock_user_config' => sub {
        my ($code, $errmsg) = @_;
        eval { $code->() };
        if (my $err = $@) {
            die "$errmsg: $err\n";
        }
    },
);

my $rpcenv = PVE::RPCEnvironment->init('cli');

# helper
sub check_roles {
    my ($user, $path, $expected_result) = @_;

    my $roles = PVE::AccessControl::roles($rpcenv->{user_cfg}, $user, $path);
    my $res = join(',', sort keys %$roles);

    is($res, $expected_result, "Roles for $user on $path should be '$expected_result'");
}

for my $test ($tests->@*) {
    subtest $test->{description} => sub {
        $mocked_user_cfg_tree = PVE::AccessControl::parse_user_config("user.cfg", $test->{raw});
        $rpcenv->{user_cfg} = $mocked_user_cfg_tree;

        eval { PVE::AccessControl::remove_sdn_resource_access($test->{prune_paths}); };
        my $err = $@;

        if ($test->{expected_error}) {
            ok($err, $test->{error_desc});
            like($err, $test->{expected_error}, "Error message matches expected string");
        } else {
            is($err, '', "Pruning completed without errors");

            $rpcenv->{user_cfg} = $mocked_user_cfg_tree;

            for my $role_check ($test->{expected_roles}->@*) {
                check_roles(@$role_check);
            }
        }
    };
}

done_testing();

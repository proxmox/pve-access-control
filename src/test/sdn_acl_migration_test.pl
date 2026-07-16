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
        description => 'successful migration of vnets and child vlans',
        raw => <<~EOF,
        user:user1\@pve:1:0::::::
        role:SDNAdmin:SDN.Allocate,SDN.Audit
        acl:1:/sdn/zones/zone1/vnet1:user1\@pve:SDNAdmin:
        acl:1:/sdn/zones/zone1/vnet2:user1\@pve:SDNAdmin:
        acl:1:/sdn/zones/zone1/vnet2/100:user1\@pve:SDNAdmin:
        acl:1:/sdn/zones/zone1/vnet2/200:user1\@pve:SDNAdmin:
        EOF
        migrations => [
            {
                src_path => 'zones/zone1/vnet1',
                dest_path => 'zones/zone2/vnet1',
            },
            {
                src_path => 'zones/zone1/vnet2',
                dest_path => 'zones/zone2/vnet2',
            },
            {
                src_path => 'zones/zone1/vnet4',
                dest_path => 'zones/zone2/vnet4',
            }, # fictional move
        ],
        expected_roles => [
            # src paths, should be empty after the migration
            ['user1@pve', '/sdn/zones/zone1/vnet1', ''],
            ['user1@pve', '/sdn/zones/zone1/vnet2', ''],
            ['user1@pve', '/sdn/zones/zone1/vnet2/100', ''],
            ['user1@pve', '/sdn/zones/zone1/vnet2/200', ''],

            # dest paths, should have the migrated permissions
            ['user1@pve', '/sdn/zones/zone2/vnet1', 'SDNAdmin'],
            ['user1@pve', '/sdn/zones/zone2/vnet2', 'SDNAdmin'],
            ['user1@pve', '/sdn/zones/zone2/vnet2/100', 'SDNAdmin'],
            ['user1@pve', '/sdn/zones/zone2/vnet2/200', 'SDNAdmin'],

            # fictional move, should be empty
            ['user1@pve', '/sdn/zones/zone1/vnet4', ''],
            ['user1@pve', '/sdn/zones/zone2/vnet4', ''],
        ],
    },
    {
        description => 'conflict without vlan tag',
        raw => <<~EOF,
        user:user1\@pve:1:0::::::
        user:user2\@pve:1:0::::::
        role:SDNAdmin:SDN.Allocate,SDN.Audit
        acl:1:/sdn/zones/zone1/vnet3:user1\@pve:SDNAdmin:
        acl:1:/sdn/zones/zone2/vnet3:user2\@pve:SDNAdmin:
        EOF
        migrations => [
            {
                src_path => 'zones/zone1/vnet3',
                dest_path => 'zones/zone2/vnet3',
            },
        ],
        expected_error => qr/already has permissions configured/,
        error_desc => 'Migration must abort if direct target destination node already exists',
    },
    {
        description => 'conflict with vlan tag',
        raw => <<~EOF,
        user:user1\@pve:1:0::::::
        user:user2\@pve:1:0::::::
        role:SDNAdmin:SDN.Allocate,SDN.Audit
        acl:1:/sdn/zones/zone1/vnet5:user1\@pve:SDNAdmin:
        acl:1:/sdn/zones/zone2/vnet5/100:user2\@pve:SDNAdmin:
        EOF
        migrations => [
            {
                src_path => 'zones/zone1/vnet5',
                dest_path => 'zones/zone2/vnet5',
            },
        ],
        expected_error => qr/already has permissions configured/,
        error_desc =>
            'Migration must abort if a child of the target destination node already exists',
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

sub test_migration {
    my ($case) = @_;

    $mocked_user_cfg_tree = PVE::AccessControl::parse_user_config("user.cfg", $case->{raw});
    $rpcenv->{user_cfg} = $mocked_user_cfg_tree;

    eval { PVE::AccessControl::migrate_sdn_resource_access($case->{migrations}); };
    my $err = $@;

    if ($case->{expected_error}) {
        ok($err, $case->{error_desc});
        like($err, $case->{expected_error}, "Error message matches expected conflict string");
    } else {
        is($err, '', "Migration completed without errors");

        $rpcenv->{user_cfg} = $mocked_user_cfg_tree;

        for my $role_check ($case->{expected_roles}->@*) {
            check_roles(@$role_check);
        }
    }
}

for my $case ($tests->@*) {
    subtest $case->{description} => sub {
        test_migration($case);
    };
}

done_testing();


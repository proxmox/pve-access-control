#!/usr/bin/perl

use v5.36;

use lib qw(..);

use Test::MockModule;
use Test::More;

use PVE::AccessControl;
use PVE::API2::ACL;
use PVE::RPCEnvironment;

# Check which ACL paths 'Permissions.Modify' allows modifying, running the API permission check and
# handler like a request does, with the cluster file system mocked out.

my $user_cfg_raw;

my $access_control_module = Test::MockModule->new('PVE::AccessControl');
$access_control_module->mock(lock_user_config => sub { $_[0]->() });

my $api_acl_module = Test::MockModule->new('PVE::API2::ACL');
$api_acl_module->mock(
    cfs_read_file => sub($file) {
        die "unexpected cfs_read_file('$file') call\n" if $file ne 'user.cfg';
        return PVE::AccessControl::parse_user_config($file, $user_cfg_raw);
    },
    cfs_write_file => sub($file, $cfg) {
        die "unexpected cfs_write_file('$file') call\n" if $file ne 'user.cfg';
        $user_cfg_raw = PVE::AccessControl::write_user_config($file, $cfg);
    },
);

my $rpcenv = PVE::RPCEnvironment->init('cli');

sub update_acl($authuser, $path) {
    $user_cfg_raw = <<~'EOF';
        user:access-admin@pve:1:0::::::
        user:admin@pve:1:0::::::

        acl:1:/:admin@pve:Administrator:
        acl:1:/access:access-admin@pve:Administrator:
        EOF
    $rpcenv->{user_cfg} = PVE::AccessControl::parse_user_config('user.cfg', $user_cfg_raw);
    $rpcenv->{aclcache} = {};
    $rpcenv->set_user($authuser);

    my $param = { path => $path, users => $authuser, roles => 'Administrator' };
    my $info = PVE::API2::ACL->map_method_by_name('update_acl');
    eval {
        $rpcenv->check_api2_permissions($info->{permissions}, $authuser, {%$param});
        PVE::API2::ACL->update_acl({%$param});
    };
    return $@;
}

is(update_acl('access-admin@pve', '/access/groups'), '', "allowed below '/access'");
like($user_cfg_raw, qr!^acl:1:/access/groups:access-admin\@pve:Administrator:$!m, 'ACL got added');

like(
    update_acl('access-admin@pve', '/'),
    qr!Permission check failed \(/, Permissions\.Modify\)!,
    "'/access' does not allow modifying the ACL of '/'",
);
like(
    update_acl('access-admin@pve', '/vms'),
    qr!Permission check failed \(/vms, Permissions\.Modify\)!,
    "'/access' does not allow modifying the ACL of a sibling path",
);

is(update_acl('admin@pve', '/'), '', "allowed on '/' with 'Permissions.Modify' on '/'");

done_testing();

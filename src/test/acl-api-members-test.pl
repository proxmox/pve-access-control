#!/usr/bin/perl

use v5.36;

use lib qw(..);

use Test::MockModule;
use Test::More;

use PVE::AccessControl;
use PVE::API2::ACL;
use PVE::RPCEnvironment;

# Exercise the member handling of the ACL update API handler with the real schema validation and
# user config parser/writer, mocking out the cluster file system.

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
$rpcenv->set_user('root@pam');

sub update_acl($param) {
    $user_cfg_raw = "user:test\@pve:1:0::::::\n\ngroup:0:test\@pve::\n";
    $rpcenv->{user_cfg} = PVE::AccessControl::parse_user_config('user.cfg', $user_cfg_raw);
    return
        eval { PVE::API2::ACL->update_acl({ path => '/vms', roles => 'PVEAuditor', %$param }) }
        // $@;
}

update_acl({ groups => '0' });
like($user_cfg_raw, qr/^acl:1:\/vms:\@0:PVEAuditor:$/m, "ACL for group '0' gets added");

my $err = update_acl({});
like($err, qr/either 'users', 'groups' or 'tokens' is required/, 'no members are rejected');

$err = update_acl({ groups => '' });
like($err, qr/either 'users', 'groups' or 'tokens' is required/, 'empty members are rejected');

done_testing();

#!/usr/bin/perl

use v5.36;

use lib qw(..);

use Test::MockModule;
use Test::More;

use PVE::AccessControl;
use PVE::RPCEnvironment;
use PVE::Tools;

# A pool named '0' must be handled like any other pool, as its name is a valid pool ID.

my $cfg_file = 'pool-name-0-test.cfg';
my $raw_cfg = PVE::Tools::file_get_contents($cfg_file);

my @warnings;
local $SIG{__WARN__} = sub { push @warnings, @_ };

my $user_cfg;
my $access_control_module = Test::MockModule->new('PVE::AccessControl');
$access_control_module->mock(
    cfs_read_file => sub($file) {
        die "unexpected cfs_read_file('$file') call\n" if $file ne 'user.cfg';
        return $user_cfg;
    },
    cfs_write_file => sub($file, $cfg) {
        die "unexpected cfs_write_file('$file') call\n" if $file ne 'user.cfg';
        $user_cfg = $cfg;
    },
    lock_user_config => sub($code, $errmsg) { $code->() },
);

sub reset_config() {
    $user_cfg = PVE::AccessControl::parse_user_config('user.cfg', $raw_cfg);
}

reset_config();
is($user_cfg->{vms}->{100}, '0', 'VM in pool 0 is not added to a second pool');
ok(!$user_cfg->{pools}->{other}->{vms}->{100}, 'duplicate VM is ignored for the second pool');
like(join('', @warnings), qr/ignore duplicate vmid '100' in pool 'other'/, 'duplicate warns');

reset_config();
PVE::AccessControl::remove_vm_access(101);
ok(!$user_cfg->{pools}->{0}->{vms}->{101}, 'removing VM access drops it from pool 0');
ok(!exists($user_cfg->{vms}->{101}), 'removing VM access drops its pool relation');

reset_config();
PVE::AccessControl::remove_vm_from_pool(101);
ok(!$user_cfg->{pools}->{0}->{vms}->{101}, 'removing VM from pool 0 works');
ok(!exists($user_cfg->{vms}->{101}), 'removing VM from pool 0 drops its pool relation');

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->init_request(userconfig => $cfg_file);
ok(
    eval { $rpcenv->check_vm_perm('eve@pve', 102, '0', ['VM.Config.Network']); 1 },
    'privileges on pool 0 count for a new guest in it',
) or diag($@);
ok(
    !eval { $rpcenv->check_vm_perm('eve@pve', 102, undef, ['VM.Config.Network']); 1 },
    'privileges on pool 0 do not count for a guest outside it',
);

done_testing();

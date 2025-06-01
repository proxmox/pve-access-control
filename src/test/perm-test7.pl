#!/usr/bin/perl -w

use strict;
use warnings;

use Getopt::Long;

use PVE::Tools;

use PVE::AccessControl;
use PVE::RPCEnvironment;

my $rpcenv = PVE::RPCEnvironment->init('cli');

my $cfgfn = "test7.cfg";
$rpcenv->init_request(userconfig => $cfgfn);

sub check_roles {
    my ($user, $path, $expected_result) = @_;

    my $roles = PVE::AccessControl::roles($rpcenv->{user_cfg}, $user, $path);
    my $res = join(',', sort keys %$roles);

    die "unexpected result\nneed '${expected_result}'\ngot '$res'\n"
        if $res ne $expected_result;

    print "ROLES:$path:$user:$res\n";
}

sub check_permissions {
    my ($user, $path, $expected_result) = @_;

    my $perm = $rpcenv->permissions($user, $path);
    my $res = join(',', sort keys %$perm);

    die "unexpected result\nneed '${expected_result}'\ngot '$res'\n"
        if $res ne $expected_result;

    $perm = $rpcenv->permissions($user, $path);
    $res = join(',', sort keys %$perm);
    die "unexpected result (compiled)\nneed '${expected_result}'\ngot '$res'\n"
        if $res ne $expected_result;

    print "PERM:$path:$user:$res\n";
}

check_roles('User1@pve', '/vms', 'Role1');
check_roles('User1@pve', '/vms/200', 'Role1');

# no pool
check_roles('User1@pve', '/vms/100', 'Role1');
# with pool
check_permissions('User1@pve', '/vms/100', '');

print "all tests passed\n";

exit(0);

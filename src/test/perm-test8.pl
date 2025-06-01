#!/usr/bin/perl -w

use strict;
use warnings;

use PVE::Tools;

use PVE::AccessControl;
use PVE::RPCEnvironment;

my $rpcenv = PVE::RPCEnvironment->init('cli');

my $cfgfn = "test8.cfg";
$rpcenv->init_request(userconfig => $cfgfn);

sub check_roles {
    my ($user, $path, $expected_result) = @_;

    my $roles = PVE::AccessControl::roles($rpcenv->{user_cfg}, $user, $path);
    my $res = join(',', sort keys %$roles);

    die "unexpected result\nneed '${expected_result}'\ngot '$res'\n"
        if $res ne $expected_result;

    print "ROLES:$path:$user:$res\n";
}

sub check_permission {
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

check_roles('max@pve', '/', '');
check_roles('max@pve', '/vms', 'vm_admin');

#user permissions overrides group permissions
check_roles('max@pve', '/vms/100', 'customer');
check_roles('max@pve', '/vms/101', 'vm_admin');

check_permission('max@pve', '/', '');
check_permission('max@pve', '/vms', 'VM.Allocate,VM.Audit,VM.Console');
check_permission('max@pve', '/vms/100', 'VM.Audit,VM.PowerMgmt');

check_permission('alex@pve', '/vms', '');
check_permission('alex@pve', '/vms/100', 'VM.Audit,VM.PowerMgmt');

check_roles('max@pve', '/vms/200', 'storage_manager');
check_roles('joe@pve', '/vms/200', 'vm_admin');
check_roles('sue@pve', '/vms/200', 'NoAccess');

check_roles('carol@pam', '/vms/200', 'NoAccess');
check_roles('carol@pam!token', '/vms/200', 'NoAccess');
check_roles('max@pve!token', '/vms/200', 'storage_manager');
check_roles('max@pve!token2', '/vms/200', 'customer');

# check intersection -> token has Administrator, but user only vm_admin
check_permission('max@pve!token2', '/vms/300', 'VM.Allocate,VM.Audit,VM.Console,VM.PowerMgmt');

print "all tests passed\n";

exit(0);


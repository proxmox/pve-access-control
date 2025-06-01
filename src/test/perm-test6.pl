#!/usr/bin/perl -w

use strict;
use warnings;

use Getopt::Long;

use PVE::Tools;

use PVE::AccessControl;
use PVE::RPCEnvironment;

my $rpcenv = PVE::RPCEnvironment->init('cli');

my $cfgfn = "test6.cfg";
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

check_roles('User1@pve', '', '');
check_roles('User2@pve', '', '');
check_roles('User3@pve', '', '');
check_roles('User4@pve', '', '');

check_roles('User1@pve', '/vms', 'RoleTEST1');
check_roles('User2@pve', '/vms', 'RoleTEST1');
check_roles('User3@pve', '/vms', 'NoAccess');
check_roles('User4@pve', '/vms', '');

check_roles('User1@pve', '/vms/100', 'RoleTEST1');
check_roles('User2@pve', '/vms/100', 'RoleTEST1');
check_roles('User3@pve', '/vms/100', 'NoAccess');
check_roles('User4@pve', '/vms/100', '');

check_roles('User1@pve', '/vms/300', 'RoleTEST1');
check_roles('User2@pve', '/vms/300', 'RoleTEST1');
check_roles('User3@pve', '/vms/300', 'NoAccess');
check_roles('User4@pve', '/vms/300', 'RoleTEST1');

check_permissions('User1@pve', '/vms/500', 'VM.Console,VM.PowerMgmt');
check_permissions('User2@pve', '/vms/500', 'VM.Console,VM.PowerMgmt');
# without pool
check_roles('User3@pve', '/vms/500', 'NoAccess');
# with pool
check_permissions('User3@pve', '/vms/500', '');
# without pool
check_roles('User4@pve', '/vms/500', '');
# with pool
check_permissions('User4@pve', '/vms/500', '');

# without pool, checking no access on parent pool
check_roles('intern@pve', '/vms/600', '');
# once more, with VM in nested pool
check_roles('intern@pve', '/vms/700', '');
# with propagated ACL
check_roles('User4@pve', '/vms/700', '');
# with pool, checking no access on parent pool
check_permissions('intern@pve', '/vms/600', '');
# once more, with VM in nested pool
check_permissions('intern@pve', '/vms/700', 'VM.Audit');
# with propagated ACL
check_permissions('User4@pve', '/vms/700', 'VM.Console');

# check nested pool permissions
check_roles('intern@pve', '/pool/marketing/interns', 'RoleINTERN');
check_roles('User4@pve', '/pool/marketing/interns', 'RoleMARKETING');

check_permissions('User1@pve', '/vms/600', 'VM.Console');
check_permissions('User2@pve', '/vms/600', 'VM.Console');
check_permissions('User3@pve', '/vms/600', '');
check_permissions('User4@pve', '/vms/600', 'VM.Console');

check_permissions('User1@pve', '/storage/store1', 'VM.Console,VM.PowerMgmt');
check_permissions('User2@pve', '/storage/store1', 'VM.PowerMgmt');
check_permissions('User3@pve', '/storage/store1', 'VM.PowerMgmt');
check_permissions('User4@pve', '/storage/store1', 'VM.Console');

check_permissions('User1@pve', '/storage/store2', 'VM.PowerMgmt');
check_permissions('User2@pve', '/storage/store2', 'VM.PowerMgmt');
check_permissions('User3@pve', '/storage/store2', 'VM.PowerMgmt');
check_permissions('User4@pve', '/storage/store2', '');

print "all tests passed\n";

exit(0);

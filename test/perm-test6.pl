#!/usr/bin/perl -w

use strict;
use PVE::Tools;
use PVE::AccessControl;
use PVE::RPCEnvironment;
use Getopt::Long;

my $rpcenv = PVE::RPCEnvironment->init('cli');

my $cfgfn = "test6.cfg";
$rpcenv->init_request(userconfig => $cfgfn);

sub check_roles {
    my ($user, $path, $expected_result) = @_;

    my @ra = $rpcenv->roles($user, $path);
    my $res = join(',', sort @ra);

    die "unexpected result\nneed '${expected_result}'\ngot '$res'\n"
	if $res ne $expected_result;

    print "ROLES:$path:$user:$res\n";
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

check_roles('User1@pve', '/vms/300', 'Role1');
check_roles('User2@pve', '/vms/300', 'RoleTEST1');
check_roles('User3@pve', '/vms/300', 'NoAccess');
check_roles('User4@pve', '/vms/300', 'Role1');

check_roles('User1@pve', '/vms/500', 'RoleDEVEL,RoleTEST1');
check_roles('User2@pve', '/vms/500', 'RoleDEVEL,RoleTEST1');
check_roles('User3@pve', '/vms/500', 'NoAccess');
check_roles('User4@pve', '/vms/500', '');

check_roles('User1@pve', '/vms/600', 'RoleMARKETING,RoleTEST1');
check_roles('User2@pve', '/vms/600', 'RoleTEST1');
check_roles('User3@pve', '/vms/600', 'NoAccess');
check_roles('User4@pve', '/vms/600', 'RoleMARKETING');

check_roles('User1@pve', '/storage/store1', 'RoleDEVEL,RoleMARKETING');
check_roles('User2@pve', '/storage/store1', 'RoleDEVEL');
check_roles('User3@pve', '/storage/store1', 'RoleDEVEL');
check_roles('User4@pve', '/storage/store1', 'RoleMARKETING');

check_roles('User1@pve', '/storage/store2', 'RoleDEVEL');
check_roles('User2@pve', '/storage/store2', 'RoleDEVEL');
check_roles('User3@pve', '/storage/store2', 'RoleDEVEL');
check_roles('User4@pve', '/storage/store2', '');

print "all tests passed\n";

exit (0);

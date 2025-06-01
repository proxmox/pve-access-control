#!/usr/bin/perl -w

use strict;
use warnings;

use Getopt::Long;

use PVE::Tools;

use PVE::AccessControl;
use PVE::RPCEnvironment;

my $rpcenv = PVE::RPCEnvironment->init('cli');

my $cfgfn = "test3.cfg";
$rpcenv->init_request(userconfig => $cfgfn);

sub check_roles {
    my ($user, $path, $expected_result) = @_;

    my $roles = PVE::AccessControl::roles($rpcenv->{user_cfg}, $user, $path);
    my $res = join(',', sort keys %$roles);

    die "unexpected result\nneed '${expected_result}'\ngot '$res'\n"
        if $res ne $expected_result;

    print "ROLES:$path:$user:$res\n";
}

check_roles('User1@pve', '', '');
check_roles('User2@pve', '', '');

check_roles('User1@pve', '/vms/300', 'Role1');
check_roles('User1@pve', '/vms/200', 'Role2');

print "all tests passed\n";

exit(0);

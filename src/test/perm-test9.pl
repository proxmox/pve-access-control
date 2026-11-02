#!/usr/bin/perl

use v5.36;

use lib qw(..);

use Test::More;

use PVE::AccessControl;
use PVE::RPCEnvironment;

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->init_request(userconfig => 'test9.cfg');

sub check_permissions($user, $path, $expected, $description) {
    my $perm = $rpcenv->permissions($user, $path);
    is(join(',', sort keys %$perm), $expected, "$user on $path: $description");
}

check_permissions('bob@pve', '/sdn/zones/zone1/vnet1', 'SDN.Use', 'wildcard covers VNet');
check_permissions('bob@pve', '/sdn/zones/zone1/vnet1/42', 'SDN.Use', 'wildcard covers tag');
check_permissions('bob@pve', '/sdn/zones/zone1/vnet2', 'SDN.Use', 'VNet member');
check_permissions('bob@pve', '/sdn/zones/zone1/vnet2/42', '', 'VNet member excludes tags');

check_permissions('alice@pve', '/sdn/zones/zone1/vnet1', 'SDN.Use', 'wildcard covers VNet');
check_permissions(
    'alice@pve',
    '/sdn/zones/zone1/vnet1/42',
    'SDN.Audit,SDN.Use',
    'tag and wildcard combine',
);
check_permissions('alice@pve', '/sdn/zones/zone1/vnet1/44', 'SDN.Use', 'wildcard covers tag');

check_permissions('carol@pve', '/sdn/zones/zone1/vnet1/43', '', 'tag NoAccess trumps wildcard');
check_permissions('carol@pve', '/sdn/zones/zone1/vnet1/44', 'SDN.Use', 'wildcard covers tag');

my $effective = $rpcenv->get_effective_permissions('bob@pve');
is_deeply(
    [sort grep { m!^/sdn/! } keys $effective->%*],
    [
        '/sdn/zones/zone1/vnet1',
        '/sdn/zones/zone1/vnet1/*',
        '/sdn/zones/zone1/vnet1/42',
        '/sdn/zones/zone1/vnet1/43',
        '/sdn/zones/zone1/vnet2',
    ],
    'effective permissions list the VNet of a wildcard member',
);

is_deeply(
    $rpcenv->compute_api_permission('bob@pve')->{sdn},
    { 'SDN.Use' => 1 },
    'API capabilities include SDN privileges from pools',
);

done_testing();

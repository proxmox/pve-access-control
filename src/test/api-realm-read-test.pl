#!/usr/bin/perl

use v5.36;

use lib qw(..);

use Test::MockModule;
use Test::More;

use PVE::AccessControl;
use PVE::API2::Domains;
use PVE::RPCEnvironment;

my $domains_raw = <<~"EOF";
    openid: oidc
    \tclient-id pve
    \tclient-key client-secret
    \tissuer-url https://idp.example.com

    pve: pve
    \ttfa type=yubico,id=42,key=yubico-secret

    pam: pam
    \ttfa type=oath
    EOF

my $domains_module = Test::MockModule->new('PVE::API2::Domains');
$domains_module->mock(
    cfs_read_file => sub($file) {
        die "unexpected cfs_read_file('$file') call\n" if $file ne 'domains.cfg';
        return PVE::Auth::Plugin->parse_config($file, $domains_raw);
    },
);

my $can_allocate;
my $rpcenv_module = Test::MockModule->new('PVE::RPCEnvironment');
$rpcenv_module->mock(get => sub { return bless {}, 'PVE::RPCEnvironment' });
$rpcenv_module->mock(get_user => sub { return 'user@pve' });
$rpcenv_module->mock(
    check => sub($self, $user, $path, $privs, $noerr) {
        die "unexpected permission check on '$path'\n" if $path ne '/access/realm';
        die "unexpected privileges @$privs\n" if "@$privs" ne 'Realm.Allocate';
        return $can_allocate;
    },
);

$can_allocate = 0;
my $oidc = PVE::API2::Domains->read({ realm => 'oidc' });
ok(!exists($oidc->{'client-key'}), 'auditor does not get the OpenID client key');
is($oidc->{'client-id'}, 'pve', 'auditor gets the OpenID client ID');
is(
    PVE::API2::Domains->read({ realm => 'pve' })->{tfa},
    'type=yubico,id=42',
    'auditor gets the Yubico config without the API key',
);
is(PVE::API2::Domains->read({ realm => 'pam' })->{tfa}, 'type=oath',
    'auditor gets the OATH config');

$can_allocate = 1;
is(
    PVE::API2::Domains->read({ realm => 'oidc' })->{'client-key'},
    'client-secret',
    'realm administrator gets the OpenID client key',
);
like(
    PVE::API2::Domains->read({ realm => 'pve' })->{tfa},
    qr/\bkey=yubico-secret\b/,
    'realm administrator gets the Yubico API key',
);

done_testing();

#!/usr/bin/perl

use v5.36;

use lib qw(..);

use Crypt::OpenSSL::RSA;
use Test::MockModule;
use Test::More;

use PVE::AccessControl;

# Check what ticket verification returns for full tickets and TFA challenges, using a throwaway
# key in place of the cluster's auth key.

my $priv = Crypt::OpenSSL::RSA->generate_key(2048);
my $pub = Crypt::OpenSSL::RSA->new_public_key($priv->get_public_key_string());

my $access_control_module = Test::MockModule->new('PVE::AccessControl');
$access_control_module->mock(
    get_privkey => sub { return $priv },
    get_pubkey => sub($old = undef) {
        return if $old;
        return wantarray ? ($pub, time()) : $pub;
    },
);

my $ticket = PVE::AccessControl::assemble_ticket('tfa!alice@pve');
is(
    scalar(PVE::AccessControl::verify_ticket($ticket)),
    'tfa!alice@pve',
    "a user name starting with 'tfa!' is not taken as TFA ticket of another user",
);
my ($user, $age, @rest) = PVE::AccessControl::verify_ticket($ticket);
is($user, 'tfa!alice@pve', 'list context returns the user');
ok(defined($age) && !@rest, 'list context returns the age and nothing else');

$ticket = PVE::AccessControl::assemble_ticket('u2f!alice@pve!verified');
is(PVE::AccessControl::verify_ticket($ticket, 1), undef, 'u2f ticket data is not a user name');

my $challenge = PVE::AccessControl::assemble_ticket('!tfa!{"totp":true}', 'alice@pve');
is(PVE::AccessControl::verify_ticket($challenge, 1), undef, 'TFA challenge is not a full ticket');
is(
    scalar(PVE::AccessControl::verify_ticket($challenge, 0, 'alice@pve')),
    '{"totp":true}',
    'TFA challenge returns its data',
);
(undef, $age) = PVE::AccessControl::verify_ticket($challenge, 0, 'alice@pve');
ok(defined($age), 'TFA challenge returns its age in list context');
is(
    PVE::AccessControl::verify_ticket($challenge, 1, 'bob@pve'),
    undef,
    'TFA challenge is bound to its user',
);

$ticket = PVE::AccessControl::assemble_ticket('alice@pve');
ok(
    !eval { PVE::AccessControl::verify_ticket($ticket, 0, 'alice@pve') },
    'full ticket is not a TFA challenge',
);

done_testing();

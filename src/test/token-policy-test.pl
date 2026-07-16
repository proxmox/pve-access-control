#!/usr/bin/perl

use v5.36;

use Test::More;
use Test::MockModule;

use PVE::AccessControl;

# tests pass the policy explicitly; keep the fallback read of datacenter.cfg from hitting a
# real pmxcfs so the cases without a policy exercise that path against an empty config
my $access_control_module = Test::MockModule->new('PVE::AccessControl');
$access_control_module->mock(
    cfs_read_file => sub($file) {
        die "unexpected cfs_read_file('$file') call\n" if $file ne 'datacenter.cfg';
        return {};
    },
);

# fixed reference time and a 90-day maximum lifetime for deterministic bounds checks
my $now = 1_000_000_000;
my $max = 90 * 24 * 60 * 60;

sub check($desc, $policy, $param, $should_die) {
    my $err;
    eval {
        PVE::AccessControl::assert_token_policy({
            ctime => $now,
            policy => $policy,
            $param->%*,
        });
        1;
    } or $err = $@;

    if ($should_die) {
        ok($err, "$desc: rejected") or diag("expected rejection but call succeeded");
    } else {
        ok(!$err, "$desc: accepted") or diag("unexpected rejection: $err");
    }
}

# no policy configured -> everything is allowed
check(
    'no policy, never-expiring full-priv token',
    undef,
    { expire => 0, 'privilege-separation' => 0 },
    0,
);
check('no policy, undef dimensions', undef, {}, 0);
check(
    'empty policy, never-expiring full-priv token',
    {},
    { expire => 0, 'privilege-separation' => 0 },
    0,
);

# require-expiry
my $req_expire = { 'require-expiry' => 1 };
check('require-expiry, no expiry', $req_expire, { expire => 0 }, 1);
check('require-expiry, future expiry', $req_expire, { expire => $now + 100 }, 0);
check('require-expiry, expiry dimension not touched', $req_expire, {}, 0);
check(
    'require-expiry, update removing the expiry',
    $req_expire,
    { expire => 0, 'current-expire' => $now + 50 },
    1,
);
check(
    'require-expiry, does not constrain privsep',
    $req_expire,
    { expire => $now + 100, 'privilege-separation' => 0 },
    0,
);

# max-lifetime implies an expiry is required and bounds how far it may reach
my $max_life = { 'max-lifetime' => $max };
check('max-lifetime, never-expiring is rejected', $max_life, { expire => 0 }, 1);
check('max-lifetime, within bound', $max_life, { expire => $now + 100 }, 0);
check('max-lifetime, exactly at bound', $max_life, { expire => $now + $max }, 0);
check('max-lifetime, one second past bound', $max_life, { expire => $now + $max + 1 }, 1);
check('max-lifetime, expiry dimension not touched', $max_life, {}, 0);
check(
    'max-lifetime, update prolonging past the bound',
    $max_life,
    { expire => $now + $max + 1, 'current-expire' => $now + 50 },
    1,
);
check('max-lifetime, expiry in the past accepted', $max_life, { expire => $now - 100 }, 0);
check(
    'max-lifetime with explicit require-expiry=0 still requires an expiry',
    { 'require-expiry' => 0, 'max-lifetime' => $max },
    { expire => 0 },
    1,
);

# the integer schema passes zero spellings like '00' through with their submitted string
# spelling, and those are true as Perl scalars; they must still count as "no expiration date"
for my $zero ('0', '00', '+0', '-0') {
    check("require-expiry, create with zero spelling '$zero'", $req_expire, { expire => $zero }, 1);
    check(
        "require-expiry, update removing the expiry via zero spelling '$zero'",
        $req_expire,
        { expire => $zero, 'current-expire' => $now + 50 },
        1,
    );
    check("max-lifetime, create with zero spelling '$zero'", $max_life, { expire => $zero }, 1);
}

# disallow-expiry-extension rejects removing or moving the expiration date later on update,
# but neither shortening it, the initial expiration date on creation, nor updates that leave the
# expiration date untouched
my $no_extension = { 'disallow-expiry-extension' => 1 };
check(
    'disallow-expiry-extension, update extending expiry',
    $no_extension,
    { expire => $now + 200, 'current-expire' => $now + 100 },
    1,
);
check(
    'disallow-expiry-extension, update extending expiry by one second',
    $no_extension,
    { expire => $now + 101, 'current-expire' => $now + 100 },
    1,
);
check(
    'disallow-expiry-extension, update removing expiry',
    $no_extension,
    { expire => 0, 'current-expire' => $now + 100 },
    1,
);
check(
    'disallow-expiry-extension, update shortening expiry',
    $no_extension,
    { expire => $now + 100, 'current-expire' => $now + 200 },
    0,
);
check(
    'disallow-expiry-extension, update moving expiry into the past',
    $no_extension,
    { expire => $now - 100, 'current-expire' => $now + 100 },
    0,
);
check(
    'disallow-expiry-extension, update setting an expiry on a token without one',
    $no_extension,
    { expire => $now + 100, 'current-expire' => 0 },
    0,
);
check(
    'disallow-expiry-extension, update not touching expiry',
    $no_extension,
    { 'current-expire' => $now + 100 },
    0,
);
check(
    'disallow-expiry-extension, creation sets expiry',
    $no_extension,
    { expire => $now + 100 },
    0,
);
check('disallow-expiry-extension, creation without expiry', $no_extension, { expire => 0 }, 0);
check(
    'disallow-expiry-extension, does not constrain privsep',
    $no_extension,
    { 'privilege-separation' => 0, 'current-expire' => $now + 100 },
    0,
);
check(
    'disallow-expiry-extension wins over a compliant extension under require-expiry',
    { 'disallow-expiry-extension' => 1, 'require-expiry' => 1 },
    { expire => $now + 200, 'current-expire' => $now + 100 },
    1,
);
check(
    'disallow-expiry-extension, shortening under max-lifetime stays allowed',
    { 'disallow-expiry-extension' => 1, 'max-lifetime' => $max },
    { expire => $now + 100, 'current-expire' => $now + 200 },
    0,
);

# require-privilege-separation
my $require_privilege_separation = { 'require-privilege-separation' => 1 };
check(
    'require-privilege-separation, full-priv token rejected',
    $require_privilege_separation,
    { 'privilege-separation' => 0 },
    1,
);
check(
    'require-privilege-separation, privsep token accepted',
    $require_privilege_separation,
    { 'privilege-separation' => 1 },
    0,
);
check(
    'require-privilege-separation, privsep dimension not touched',
    $require_privilege_separation,
    {},
    0,
);
check(
    'require-privilege-separation, does not constrain expiry',
    $require_privilege_separation,
    { expire => 0, 'privilege-separation' => 1 },
    0,
);

# combined policy, as an admin would set for a compliance baseline
my $full = { 'require-expiry' => 1, 'max-lifetime' => $max, 'require-privilege-separation' => 1 };
check(
    'full policy, compliant token',
    $full,
    { expire => $now + 100, 'privilege-separation' => 1 },
    0,
);
check('full policy, missing expiry', $full, { expire => 0, 'privilege-separation' => 1 }, 1);
check(
    'full policy, expiry too far out',
    $full,
    { expire => $now + $max + 1, 'privilege-separation' => 1 },
    1,
);
check(
    'full policy, full-priv token',
    $full,
    { expire => $now + 100, 'privilege-separation' => 0 },
    1,
);
# partial updates only check what they change
check(
    'full policy, update touching only a valid expiry',
    $full,
    { expire => $now + 100, 'current-expire' => $now + 50 },
    0,
);
check(
    'full policy, update touching only privsep',
    $full,
    { 'privilege-separation' => 1, 'current-expire' => $now + 50 },
    0,
);

done_testing();

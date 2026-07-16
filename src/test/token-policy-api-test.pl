#!/usr/bin/perl

use v5.36;

use Test::More;
use Test::MockModule;

use PVE::AccessControl;
use PVE::API2::User;
use PVE::RPCEnvironment;

# Exercise the token create and update API handlers with the real schema validation and user
# config parser/writer, mocking out the cluster file system and secret generation. The integer
# schema accepts zero spellings like '00', '+0', or '-0' without canonicalizing them, so the
# policy enforcement at the API boundary must not mistake them for a set expiration date.

my ($policy, $user_cfg_raw, $secret_calls);

my $read = sub($file) {
    return PVE::AccessControl::parse_user_config($file, $user_cfg_raw) if $file eq 'user.cfg';
    return { 'token-policy' => $policy } if $file eq 'datacenter.cfg';
    die "unexpected cfs_read_file('$file') call\n";
};

my $access_control_module = Test::MockModule->new('PVE::AccessControl');
$access_control_module->mock(cfs_read_file => $read);
$access_control_module->mock(lock_user_config => sub { $_[0]->() });

my $api_user_module = Test::MockModule->new('PVE::API2::User');
$api_user_module->mock(cfs_read_file => $read);
$api_user_module->mock(
    cfs_write_file => sub($file, $cfg) {
        die "unexpected cfs_write_file('$file') call\n" if $file ne 'user.cfg';
        $user_cfg_raw = PVE::AccessControl::write_user_config($file, $cfg);
    },
);

my $token_config_module = Test::MockModule->new('PVE::TokenConfig');
$token_config_module->mock(
    generate_token => sub($tokenid) {
        $secret_calls++;
        return 'test-secret';
    },
);

# the handlers act on behalf of the requesting user, here the owner of the tokens
my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->set_user('test@pve');

my $reset = sub($test_policy, $expire = undef) {
    $policy = $test_policy;
    $user_cfg_raw = "user:test\@pve:1:0::::::\n";
    $user_cfg_raw .= "token:test\@pve!old:$expire:1:some comment:\n" if defined($expire);
    $secret_calls = 0;
};

my $invoke = sub($method, $param) {
    my $ok = eval {
        PVE::API2::User->$method({ userid => 'test@pve', %$param });
        1;
    };
    return ($ok, $@);
};

my $now = time();

for my $policy_variant ({ 'require-expiry' => 1 }, { 'max-lifetime' => 86400 }) {
    my $desc = join(',', map { "$_=$policy_variant->{$_}" } sort keys $policy_variant->%*);

    for my $zero ('0', '00', '+0', '-0') {
        $reset->($policy_variant);
        my ($ok, $err) = $invoke->('generate_token', { tokenid => 'new', expire => $zero });
        ok(
            !$ok && $err =~ /requires an expiration date/,
            "$desc: create with expire=$zero rejected",
        );
        is($secret_calls, 0, "$desc: rejected create generates no secret");
        ok($user_cfg_raw !~ /!new/, "$desc: rejected create writes no token");

        $reset->($policy_variant, $now + 600);
        my $before = $user_cfg_raw;
        ($ok, $err) =
            $invoke->('update_token_info', { tokenid => 'old', expire => $zero, regenerate => 1 });
        ok(
            !$ok && $err =~ /requires an expiration date/, "$desc: update to expire=$zero rejected",
        );
        is($secret_calls, 0, "$desc: rejected update rotates no secret");
        is($user_cfg_raw, $before, "$desc: rejected update writes nothing");
    }

    $reset->($policy_variant);
    my ($ok, $err) = $invoke->('generate_token', { tokenid => 'new', expire => $now + 600 });
    ok($ok, "$desc: compliant create accepted") or diag($err);
    is($secret_calls, 1, "$desc: accepted create generates a secret");
}

# unrelated updates of a token that predates the policy must keep working
$reset->({ 'require-expiry' => 1 }, 0);
my ($ok, $err) = $invoke->('update_token_info', { tokenid => 'old', comment => 'changed' });
ok($ok, 'unrelated update of a non-conforming token stays allowed') or diag($err);

# disallow-expiry-extension only forbids what would prolong a token
$reset->({ 'disallow-expiry-extension' => 1 }, $now + 600);
($ok, $err) = $invoke->('update_token_info', { tokenid => 'old', expire => $now + 1200 });
ok(!$ok && $err =~ /does not allow extending/, 'extending the expiry is rejected');
($ok, $err) = $invoke->('update_token_info', { tokenid => 'old', expire => 0 });
ok(!$ok && $err =~ /does not allow extending/, 'removing the expiry is rejected');
($ok, $err) = $invoke->('update_token_info', { tokenid => 'old', expire => $now + 300 });
ok($ok, 'shortening the expiry stays allowed') or diag($err);
($ok, $err) = $invoke->('update_token_info', { tokenid => 'old', expire => $now + 300 });
ok($ok, 'resubmitting the unchanged expiry stays allowed') or diag($err);
$reset->({ 'disallow-expiry-extension' => 1 }, 0);
($ok, $err) = $invoke->('update_token_info', { tokenid => 'old', expire => $now + 600 });
ok($ok, 'setting an expiry on a token without one stays allowed') or diag($err);

done_testing();

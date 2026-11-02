#!/usr/bin/perl

use v5.36;

use lib qw(..);

use Storable qw(dclone);
use Test::MockModule;
use Test::More;

use PVE::Auth::PVE;
use PVE::Tools;

my $legacy_hash = PVE::Tools::encrypt_pw('secret', '5');
my $current_hash = PVE::Tools::encrypt_pw('secret', 'y');
my $other_hash = PVE::Tools::encrypt_pw('other', 'y');

my $shadow;
my $writes;
my $quorate;
my $lock_error;
my $before_locked_code; # simulates changes done by others before the lock is acquired
my $lock_attempts;

my $cluster_mock = Test::MockModule->new('PVE::Cluster');
$cluster_mock->redefine(check_cfs_quorum => sub { return $quorate });

my $plugin_mock = Test::MockModule->new('PVE::Auth::PVE');
$plugin_mock->redefine(
    cfs_read_file => sub { return dclone($shadow) },
    cfs_write_file => sub {
        my ($filename, $cfg) = @_;
        $shadow = dclone($cfg);
        $writes++;
    },
    cfs_lock_file => sub {
        my ($filename, $timeout, $code) = @_;
        $lock_attempts++;
        if ($lock_error) {
            $@ = "cfs-lock 'file-priv_shadow_cfg' error: $lock_error\n";
            return undef;
        }
        $before_locked_code->() if $before_locked_code;
        my $res = eval { $code->() };
        return $res;
    },
);

sub run_test($description, $setup, $check) {
    $shadow = { users => { alice => { shadow => $legacy_hash } } };
    $writes = 0;
    $quorate = 1;
    $lock_error = undef;
    $before_locked_code = undef;
    $lock_attempts = 0;

    $setup->();

    my @warnings;
    local $SIG{__WARN__} = sub { push @warnings, @_ };

    my $res = eval { PVE::Auth::PVE->authenticate_user({}, 'pve', 'alice', 'secret') };
    my $err = $@;

    subtest $description => sub { $check->($res, $err, \@warnings) };
}

run_test(
    'legacy hash gets upgraded',
    sub { },
    sub($res, $err, $warnings) {
        is($err, '', 'login succeeds');
        is($writes, 1, 'shadow config written once');
        my $new_hash = $shadow->{users}->{alice}->{shadow};
        like($new_hash, qr/^\$y\$/, 'stored hash uses yescrypt');
        is(crypt('secret', $new_hash), $new_hash, 'new hash verifies the password');
        is_deeply($warnings, [], 'no warnings');
    },
);

run_test(
    'current hash is left alone',
    sub { $shadow->{users}->{alice}->{shadow} = $current_hash },
    sub($res, $err, $warnings) {
        is($err, '', 'login succeeds');
        is($lock_attempts, 0, 'no lock taken');
        is($writes, 0, 'nothing written');
    },
);

run_test(
    'wrong password does not upgrade',
    sub { $shadow->{users}->{alice}->{shadow} = $other_hash },
    sub($res, $err, $warnings) {
        like($err, qr/invalid credentials/, 'login fails');
        is($lock_attempts, 0, 'no lock taken');
        is($writes, 0, 'nothing written');
    },
);

run_test(
    'no quorum keeps legacy hash and accepts login',
    sub { $quorate = 0 },
    sub($res, $err, $warnings) {
        is($err, '', 'login succeeds');
        is($lock_attempts, 0, 'no lock attempted');
        is($writes, 0, 'nothing written');
        is($shadow->{users}->{alice}->{shadow}, $legacy_hash, 'legacy hash kept');
    },
);

run_test(
    'lock failure keeps legacy hash and accepts login',
    sub { $lock_error = 'got lock request timeout' },
    sub($res, $err, $warnings) {
        is($err, '', 'login succeeds');
        is($writes, 0, 'nothing written');
        is(scalar(@$warnings), 1, 'one warning');
        like($warnings->[0], qr/failed to upgrade password hash of user 'alice\@pve'/, 'warns');
    },
);

run_test(
    'concurrent password change is not overwritten',
    sub {
        $before_locked_code = sub { $shadow->{users}->{alice}->{shadow} = $other_hash };
    },
    sub($res, $err, $warnings) {
        is($err, '', 'login succeeds');
        is($writes, 0, 'nothing written');
        is($shadow->{users}->{alice}->{shadow}, $other_hash, 'changed hash kept');
    },
);

run_test(
    'concurrently removed user is not re-added',
    sub {
        $before_locked_code = sub { delete $shadow->{users}->{alice} };
    },
    sub($res, $err, $warnings) {
        is($err, '', 'login succeeds');
        is($writes, 0, 'nothing written');
        ok(!exists($shadow->{users}->{alice}), 'user stays removed');
    },
);

done_testing();

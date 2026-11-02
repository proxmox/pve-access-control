package PVE::Auth::PVE;

use strict;
use warnings;
use Encode;

use PVE::Tools;
use PVE::Auth::Plugin;
use PVE::Cluster qw(cfs_register_file cfs_read_file cfs_write_file cfs_lock_file);

use base qw(PVE::Auth::Plugin);

my $shadowconfigfile = "priv/shadow.cfg";
my $hash_prefix = "y";

cfs_register_file($shadowconfigfile, \&parse_shadow_passwd, \&write_shadow_config);

sub parse_shadow_passwd {
    my ($filename, $raw) = @_;

    my $shadow = {};

    return $shadow if !defined($raw);

    while ($raw =~ /^\s*(.+?)\s*$/gm) {
        my $line = $1;

        if ($line !~ m/^\S+:\S+:$/) {
            warn "pve shadow password: ignore invalid line $.\n";
            next;
        }

        my ($userid, $crypt_pass) = split(/:/, $line);
        $shadow->{users}->{$userid}->{shadow} = $crypt_pass;
    }

    return $shadow;
}

sub write_shadow_config {
    my ($filename, $cfg) = @_;

    my $data = '';
    foreach my $userid (keys %{ $cfg->{users} }) {
        my $crypt_pass = $cfg->{users}->{$userid}->{shadow};
        $data .= "$userid:$crypt_pass:\n";
    }

    return $data;
}

sub lock_shadow_config {
    my ($code, $errmsg) = @_;

    cfs_lock_file($shadowconfigfile, undef, $code);
    my $err = $@;
    if ($err) {
        $errmsg ? die "$errmsg: $err" : die $err;
    }
}

sub type {
    return 'pve';
}

sub options {
    return {
        default => { optional => 1 },
        comment => { optional => 1 },
        tfa => { optional => 1 },
    };
}

# Re-hash an already verified password with the current hash function. This is best-effort, as
# failing here, for example without quorum, must not reject valid credentials. Only the verified
# hash gets replaced, as a concurrent password change or user removal could have changed it since.
my sub upgrade_password_hash {
    my ($realm, $username, $password, $verified_hash) = @_;

    # avoid waiting for the lock timeout on every such login while the cluster is not quorate
    return if !PVE::Cluster::check_cfs_quorum(1);

    eval {
        lock_shadow_config(sub {
            my $shadow_cfg = cfs_read_file($shadowconfigfile);
            my $entry = $shadow_cfg->{users}->{$username};
            return if !defined($entry) || $entry->{shadow} ne $verified_hash;

            $entry->{shadow} = PVE::Tools::encrypt_pw($password, $hash_prefix);
            cfs_write_file($shadowconfigfile, $shadow_cfg);
        });
    };
    warn "failed to upgrade password hash of user '$username\@$realm' - $@" if $@;
}

sub authenticate_user {
    my ($class, $config, $realm, $username, $password) = @_;

    die "no password\n" if !$password;

    my $shadow_cfg = cfs_read_file($shadowconfigfile);

    if ($shadow_cfg->{users}->{$username}) {
        my $stored_hash = $shadow_cfg->{users}->{$username}->{shadow};
        my $encpw = crypt(Encode::encode('utf8', $password), $stored_hash);
        die "invalid credentials\n" if ($encpw ne $stored_hash);

        if ($stored_hash !~ m/^\$${hash_prefix}\$/) {
            upgrade_password_hash($realm, $username, $password, $stored_hash);
        }
    } else {
        die "no password set\n";
    }

    return 1;
}

sub store_password {
    my ($class, $config, $realm, $username, $password) = @_;

    lock_shadow_config(sub {
        my $shadow_cfg = cfs_read_file($shadowconfigfile);
        my $epw = PVE::Tools::encrypt_pw($password, $hash_prefix);
        $shadow_cfg->{users}->{$username}->{shadow} = $epw;
        cfs_write_file($shadowconfigfile, $shadow_cfg);
    });
}

sub delete_user {
    my ($class, $config, $realm, $username) = @_;

    lock_shadow_config(sub {
        my $shadow_cfg = cfs_read_file($shadowconfigfile);

        delete $shadow_cfg->{users}->{$username};

        cfs_write_file($shadowconfigfile, $shadow_cfg);
    });
}

1;

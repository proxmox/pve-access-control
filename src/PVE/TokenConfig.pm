package PVE::TokenConfig;

use strict;
use warnings;

use UUID;

use PVE::AccessControl;
use PVE::Cluster;

my $parse_token_cfg = sub {
    my ($filename, $raw) = @_;

    my $parsed = {};
    return $parsed if !defined($raw);

    my @lines = split(/\n/, $raw);
    foreach my $line (@lines) {
        next if $line =~ m/^\s*$/;

        if ($line =~ m/^(\S+) (\S+)$/) {
            if (PVE::AccessControl::pve_verify_tokenid($1, 1)) {
                $parsed->{$1} = $2;
                next;
            }
        }

        warn "skipping invalid token.cfg entry\n";
    }

    return $parsed;
};

my $write_token_cfg = sub {
    my ($filename, $data) = @_;

    my $raw = '';
    foreach my $tokenid (sort keys %$data) {
        $raw .= "$tokenid $data->{$tokenid}\n";
    }

    return $raw;
};

PVE::Cluster::cfs_register_file('priv/token.cfg', $parse_token_cfg, $write_token_cfg);

sub generate_token {
    my ($tokenid) = @_;

    PVE::AccessControl::pve_verify_tokenid($tokenid);

    my $token_value = PVE::Cluster::cfs_lock_file(
        'priv/token.cfg',
        10,
        sub {
            my $uuid = UUID::uuid();
            my $token_cfg = PVE::Cluster::cfs_read_file('priv/token.cfg');

            $token_cfg->{$tokenid} = $uuid;

            PVE::Cluster::cfs_write_file('priv/token.cfg', $token_cfg);

            return $uuid;
        },
    );

    die "$@\n" if defined($@);

    return $token_value;
}

sub delete_token {
    my ($tokenid) = @_;

    PVE::Cluster::cfs_lock_file(
        'priv/token.cfg',
        10,
        sub {
            my $token_cfg = PVE::Cluster::cfs_read_file('priv/token.cfg');

            delete $token_cfg->{$tokenid};

            PVE::Cluster::cfs_write_file('priv/token.cfg', $token_cfg);
        },
    );

    die "$@\n" if defined($@);
}

package PVE::Auth::AD;

use strict;
use warnings;
use PVE::Auth::LDAP;
use PVE::LDAP;

use base qw(PVE::Auth::LDAP);

sub type {
    return 'ad';
}

sub properties {
    return {
        server1 => {
            description => "Server IP address (or DNS name)",
            type => 'string',
            format => 'address',
            maxLength => 256,
        },
        server2 => {
            description => "Fallback Server IP address (or DNS name)",
            type => 'string',
            optional => 1,
            format => 'address',
            maxLength => 256,
        },
        secure => {
            description => "Use secure LDAPS protocol. DEPRECATED: use 'mode' instead.",
            type => 'boolean',
            optional => 1,
        },
        sslversion => {
            description =>
                "LDAPS TLS/SSL version. It's not recommended to use version older than 1.2!",
            type => 'string',
            enum => [qw(tlsv1 tlsv1_1 tlsv1_2 tlsv1_3)],
            optional => 1,
        },
        default => {
            description => "Use this as default realm",
            type => 'boolean',
            optional => 1,
        },
        comment => {
            description => "Description.",
            type => 'string',
            optional => 1,
            maxLength => 4096,
        },
        port => {
            description => "Server port.",
            type => 'integer',
            minimum => 1,
            maximum => 65535,
            optional => 1,
        },
        domain => {
            description => "AD domain name",
            type => 'string',
            pattern => '\S+',
            optional => 1,
            maxLength => 256,
        },
        tfa => PVE::JSONSchema::get_standard_option('tfa'),
    };
}

sub options {
    return {
        server1 => {},
        server2 => { optional => 1 },
        domain => {},
        port => { optional => 1 },
        secure => { optional => 1 },
        sslversion => { optional => 1 },
        default => { optional => 1 },
        comment => { optional => 1 },
        tfa => { optional => 1 },
        verify => { optional => 1 },
        capath => { optional => 1 },
        cert => { optional => 1 },
        certkey => { optional => 1 },
        base_dn => { optional => 1 },
        bind_dn => { optional => 1 },
        password => { optional => 1 },
        user_attr => { optional => 1 },
        filter => { optional => 1 },
        sync_attributes => { optional => 1 },
        user_classes => { optional => 1 },
        group_dn => { optional => 1 },
        group_name_attr => { optional => 1 },
        group_filter => { optional => 1 },
        group_classes => { optional => 1 },
        'sync-defaults-options' => { optional => 1 },
        mode => { optional => 1 },
        'case-sensitive' => { optional => 1 },
    };
}

sub get_users {
    my ($class, $config, $realm) = @_;

    $config->{user_attr} //= 'sAMAccountName';

    return $class->SUPER::get_users($config, $realm);
}

sub authenticate_user {
    my ($class, $config, $realm, $username, $password) = @_;

    my $servers = [$config->{server1}];
    push @$servers, $config->{server2} if $config->{server2};

    my ($scheme, $port) = $class->get_scheme_and_port($config);

    my %ad_args;
    if ($config->{verify}) {
        $ad_args{verify} = 'require';
        $ad_args{clientcert} = $config->{cert} if $config->{cert};
        $ad_args{clientkey} = $config->{certkey} if $config->{certkey};
        if (defined(my $capath = $config->{capath})) {
            if (-d $capath) {
                $ad_args{capath} = $capath;
            } else {
                $ad_args{cafile} = $capath;
            }
        }
    } elsif (defined($config->{verify})) {
        $ad_args{verify} = 'none';
    }

    if ($scheme ne 'ldap') {
        $ad_args{sslversion} = $config->{sslversion} // 'tlsv1_2';
    }

    my $ldap = PVE::LDAP::ldap_connect($servers, $scheme, $port, \%ad_args);

    $username = "$username\@$config->{domain}"
        if $username !~ m/@/ && $config->{domain};

    PVE::LDAP::auth_user_dn($ldap, $username, $password);

    $ldap->unbind();
    return 1;
}

1;

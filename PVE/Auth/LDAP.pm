package PVE::Auth::LDAP;

use strict;
use warnings;

use PVE::Tools;
use PVE::Auth::Plugin;
use Net::LDAP;
use Net::IP;
use base qw(PVE::Auth::Plugin);

sub type {
    return 'ldap';
}

sub properties {
    return {
	base_dn => {
	    description => "LDAP base domain name",
	    type => 'string',
	    pattern => '\w+=[^,]+(,\s*\w+=[^,]+)*',
	    optional => 1,
	    maxLength => 256,
	},
	user_attr => {
	    description => "LDAP user attribute name",
	    type => 'string',
	    pattern => '\S{2,}',
	    optional => 1,
	    maxLength => 256,
	},
	bind_dn => {
	    description => "LDAP bind domain name",
	    type => 'string',
	    pattern => '\w+=[^,]+(,\s*\w+=[^,]+)*',
	    optional => 1,
	    maxLength => 256,
	},
    };
}

sub options {
    return {
	server1 => {},
	server2 => { optional => 1 },
	base_dn => {},
	bind_dn => { optional => 1 },
	user_attr => {},
	port => { optional => 1 },
	secure => { optional => 1 },
	default => { optional => 1 },
	comment => { optional => 1 },
	tfa => { optional => 1 },
    };
}

my $authenticate_user_ldap = sub {
    my ($config, $server, $username, $password, $realm) = @_;

    my $default_port = $config->{secure} ? 636: 389;
    my $port = $config->{port} ? $config->{port} : $default_port;
    my $scheme = $config->{secure} ? 'ldaps' : 'ldap';
    $server = "[$server]" if Net::IP::ip_is_ipv6($server);
    my $conn_string = "$scheme://${server}:$port";

    my $ldap = Net::LDAP->new($conn_string, verify => 'none') || die "$@\n";

    if (my $bind_dn = $config->{bind_dn}) {
	my $bind_pass = PVE::Tools::file_read_firstline("/etc/pve/priv/ldap/${realm}.pw");
	die "missing password for realm $realm\n" if !defined($bind_pass);
	my $res = $ldap->bind($bind_dn, password => $bind_pass);
	my $code = $res->code();
	my $err = $res->error;
	die "failed to authenticate to ldap service: $err\n" if ($code);
    }

    my $search = $config->{user_attr} . "=" . $username;
    my $result = $ldap->search( base    => "$config->{base_dn}",
				scope   => "sub",
				filter  => "$search",
				attrs   => ['dn']
				);
    die "no entries returned\n" if !$result->entries;
    my @entries = $result->entries;
    my $res = $ldap->bind($entries[0]->dn, password => $password);

    my $code = $res->code();
    my $err = $res->error;

    $ldap->unbind();

    die "$err\n" if ($code);
};

sub authenticate_user {
    my ($class, $config, $realm, $username, $password) = @_;

    eval { &$authenticate_user_ldap($config, $config->{server1}, $username, $password, $realm); };
    my $err = $@;
    return 1 if !$err;
    die $err if !$config->{server2};
    &$authenticate_user_ldap($config, $config->{server2}, $username, $password); 
}

1;

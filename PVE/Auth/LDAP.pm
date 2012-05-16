package PVE::Auth::LDAP;

use strict;
use PVE::Auth::Plugin;
use Net::LDAP;
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
    };
}

sub options {
    return {
	server1 => {},
	server2 => { optional => 1 },
	base_dn => {},
	user_attr => {},
	port => { optional => 1 },
	secure => { optional => 1 },
	default => { optional => 1 },
	comment => { optional => 1 },
    };
}

my $authenticate_user_ldap = sub {
    my ($config, $server, $username, $password) = @_;

    my $default_port = $config->{secure} ? 636: 389;
    my $port = $config->{port} ? $config->{port} : $default_port;
    my $scheme = $config->{secure} ? 'ldaps' : 'ldap';
    my $conn_string = "$scheme://${server}:$port";

    my $ldap = Net::LDAP->new($conn_string, verify => 'none') || die "$@\n";
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

    eval { &$authenticate_user_ldap($config, $config->{server1}, $username, $password); };
    my $err = $@;
    return 1 if !$err;
    die $err if !$config->{server2};
    &$authenticate_user_ldap($config, $config->{server2}, $username, $password); 
}

1;

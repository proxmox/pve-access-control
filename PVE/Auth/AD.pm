package PVE::Auth::AD;

use strict;
use warnings;
use PVE::Auth::Plugin;
use Net::LDAP;
use Net::IP;

use base qw(PVE::Auth::Plugin);

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
	    description => "Use secure LDAPS protocol.",
	    type => 'boolean',
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
	default => { optional => 1 },,
	comment => { optional => 1 },
	tfa => { optional => 1 },
	verify => { optional => 1 },
	capath => { optional => 1 },
	cert => { optional => 1 },
	certkey => { optional => 1 },
    };
}

my $authenticate_user_ad = sub {
    my ($config, $server, $username, $password) = @_;

    my $default_port = $config->{secure} ? 636: 389;
    my $port = $config->{port} ? $config->{port} : $default_port;
    my $scheme = $config->{secure} ? 'ldaps' : 'ldap';
    $server = "[$server]" if Net::IP::ip_is_ipv6($server);
    my $conn_string = "$scheme://${server}:$port";

    my %ad_args;
    if ($config->{verify}) {
	$ad_args{verify} = 'require';
	if (defined(my $cert = $config->{cert})) {
	    $ad_args{clientcert} = $cert;
	}
	if (defined(my $key = $config->{certkey})) {
	    $ad_args{clientkey} = $key;
	}
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

    my $ldap = Net::LDAP->new($conn_string, %ad_args) || die "$@\n";

    $username = "$username\@$config->{domain}"
	if $username !~ m/@/ && $config->{domain};

    my $res = $ldap->bind($username, password => $password);

    my $code = $res->code();
    my $err = $res->error;

    $ldap->unbind();

    die "$err\n" if ($code);
};

sub authenticate_user {
    my ($class, $config, $realm, $username, $password) = @_;

    eval { &$authenticate_user_ad($config, $config->{server1}, $username, $password); };
    my $err = $@;
    return 1 if !$err;
    die $err if !$config->{server2};
    &$authenticate_user_ad($config, $config->{server2}, $username, $password);
    return 1;
}

1;

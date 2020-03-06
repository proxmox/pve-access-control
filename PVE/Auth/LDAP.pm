package PVE::Auth::LDAP;

use strict;
use warnings;

use PVE::Tools;
use PVE::Auth::Plugin;
use PVE::LDAP;
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
	verify => {
	    description => "Verify the server's SSL certificate",
	    type => 'boolean',
	    optional => 1,
	    default => 0,
	},
	capath => {
	    description => "Path to the CA certificate store",
	    type => 'string',
	    optional => 1,
	    default => '/etc/ssl/certs',
	},
	cert => {
	    description => "Path to the client certificate",
	    type => 'string',
	    optional => 1,
	},
	certkey => {
	    description => "Path to the client certificate key",
	    type => 'string',
	    optional => 1,
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
	sslversion => { optional => 1 },
	default => { optional => 1 },
	comment => { optional => 1 },
	tfa => { optional => 1 },
	verify => { optional => 1 },
	capath => { optional => 1 },
	cert => { optional => 1 },
	certkey => { optional => 1 },
    };
}

sub connect_and_bind {
    my ($class, $config, $realm) = @_;

    my $servers = [$config->{server1}];
    push @$servers, $config->{server2} if $config->{server2};

    my $default_port = $config->{secure} ? 636: 389;
    my $port = $config->{port} // $default_port;
    my $scheme = $config->{secure} ? 'ldaps' : 'ldap';

    my %ldap_args;
    if ($config->{verify}) {
	$ldap_args{verify} = 'require';
	$ldap_args{clientcert} = $config->{cert} if $config->{cert};
	$ldap_args{clientkey} = $config->{certkey} if $config->{certkey};
	if (defined(my $capath = $config->{capath})) {
	    if (-d $capath) {
		$ldap_args{capath} = $capath;
	    } else {
		$ldap_args{cafile} = $capath;
	    }
	}
    } else {
	$ldap_args{verify} = 'none';
    }

    if ($config->{secure}) {
	$ldap_args{sslversion} = $config->{sslversion} || 'tlsv1_2';
    }

    my $ldap = PVE::LDAP::ldap_connect($servers, $scheme, $port, \%ldap_args);

    my $bind_dn;
    my $bind_pass;

    if ($config->{bind_dn}) {
	$bind_dn = $config->{bind_dn};
	$bind_pass = PVE::Tools::file_read_firstline("/etc/pve/priv/ldap/${realm}.pw");
	die "missing password for realm $realm\n" if !defined($bind_pass);
    }

    PVE::LDAP::ldap_bind($ldap, $bind_dn, $bind_pass);

    if (!$config->{base_dn}) {
	my $root = $ldap->root_dse(attrs => [ 'defaultNamingContext' ]);
	$config->{base_dn} = $root->get_value('defaultNamingContext');
    }

    return $ldap;
}

sub authenticate_user {
    my ($class, $config, $realm, $username, $password) = @_;

    my $ldap = $class->connect_and_bind($config, $realm);

    my $user_dn = PVE::LDAP::get_user_dn($ldap, $username, $config->{user_attr}, $config->{base_dn});
    PVE::LDAP::auth_user_dn($ldap, $user_dn, $password);

    $ldap->unbind();
    return 1;
}

1;

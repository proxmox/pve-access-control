package PVE::API2::Domains;

use strict;
use warnings;
use PVE::Cluster qw (cfs_read_file cfs_write_file);
use PVE::AccessControl;
use PVE::JSONSchema qw(get_standard_option);

use PVE::SafeSyslog;

use Data::Dumper; # fixme: remove

use PVE::RESTHandler;

my $domainconfigfile = "domains.cfg";

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index', 
    path => '', 
    method => 'GET',
    description => "Authentication domain index.",
    permissions => { user => 'world' },
    parameters => {
	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		realm => { type => 'string' },
		comment => { type => 'string', optional => 1 },
	    },
	},
	links => [ { rel => 'child', href => "{realm}" } ],
    },
    code => sub {
	my ($param) = @_;
    
	my $res = [];

	my $cfg = cfs_read_file($domainconfigfile);
 
	foreach my $realm (keys %$cfg) {
	    my $d = $cfg->{$realm};
	    my $entry = { realm => $realm, type => $d->{type} };
	    $entry->{comment} = $d->{comment} if $d->{comment};
	    $entry->{default} = 1 if $d->{default};
	    push @$res, $entry;
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'create', 
    protected => 1,
    path => '', 
    method => 'POST',
    description => "Add an authentication server.",
    parameters => {
   	additionalProperties => 0,
	properties => {
	    realm =>  get_standard_option('realm'),
	    type => {
		description => "Server type.",
		type => 'string', 
		enum => [ 'ad', 'ldap' ],
	    },
	    server1 => { 
		description => "Server IP address (or DNS name)",		
		type => 'string',
	    },
	    server2 => { 
		description => "Fallback Server IP address (or DNS name)",
		type => 'string',
		optional => 1,
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
		type => 'string', 
		optional => 1,
	    },
	    port => {
		description => "Server port. Use '0' if you want to use default settings'",
		type => 'integer',
		minimum => 0,
		maximum => 65535,
		optional => 1,
	    },
	    domain => {
		description => "AD domain name",
		type => 'string',
		optional => 1,
	    },
	    base_dn => {
		description => "LDAP base domain name",
		type => 'string',
		optional => 1,
	    },
	    user_attr => {
		description => "LDAP user attribute name",
		type => 'string',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PVE::AccessControl::lock_domain_config(
	    sub {
			
		my $cfg = cfs_read_file($domainconfigfile);

		my $realm = $param->{realm};
	
		die "domain '$realm' already exists\n" 
		    if $cfg->{$realm};

		die "unable to use reserved name '$realm'\n"
		    if ($realm eq 'pam' || $realm eq 'pve');

		if (defined($param->{secure})) {
		    $cfg->{$realm}->{secure} = $param->{secure} ? 1 : 0;
		}

		if ($param->{default}) {
		    foreach my $r (keys %$cfg) {
			delete $cfg->{$r}->{default};
		    }
		}

		foreach my $p (keys %$param) {
		    next if $p eq 'realm';
		    $cfg->{$realm}->{$p} = $param->{$p};
		}

		# port 0 ==> use default
		if (defined($param->{port}) && !$param->{port}) { 
		    delete $cfg->{$realm}->{port};
		}

		cfs_write_file($domainconfigfile, $cfg);
	    }, "add auth server failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'update', 
    path => '{realm}', 
    method => 'PUT',
    description => "Update authentication server settings.",
    protected => 1,
    parameters => {
   	additionalProperties => 0,
	properties => {
	    realm =>  get_standard_option('realm'),
	    server1 => { 
		description => "Server IP address (or DNS name)",		
		type => 'string',
		optional => 1,
	    },
	    server2 => { 
		description => "Fallback Server IP address (or DNS name)",
		type => 'string',
		optional => 1,
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
		type => 'string', 
		optional => 1,
	    },
	    port => {
		description => "Server port. Use '0' if you want to use default settings'",
		type => 'integer',
		minimum => 0,
		maximum => 65535,
		optional => 1,
	    },
	    domain => {
		description => "AD domain name",
		type => 'string',
		optional => 1,
	    },
	    base_dn => {
		description => "LDAP base domain name",
		type => 'string',
		optional => 1,
	    },
	    user_attr => {
		description => "LDAP user attribute name",
		type => 'string',
		optional => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PVE::AccessControl::lock_domain_config(
	    sub {
			
		my $cfg = cfs_read_file($domainconfigfile);

		my $realm = $param->{realm};
		delete $param->{realm};

		die "unable to modify bultin domain '$realm'\n"
		    if ($realm eq 'pam' || $realm eq 'pve');

		die "domain '$realm' does not exist\n" 
		    if !$cfg->{$realm};

		if (defined($param->{secure})) {
		    $cfg->{$realm}->{secure} = $param->{secure} ? 1 : 0;
		}

		if ($param->{default}) {
		    foreach my $r (keys %$cfg) {
			delete $cfg->{$r}->{default};
		    }
		}

		foreach my $p (keys %$param) {
		    $cfg->{$realm}->{$p} = $param->{$p};
		}

		# port 0 ==> use default
		if (defined($param->{port}) && !$param->{port}) { 
		    delete $cfg->{$realm}->{port};
		}

		cfs_write_file($domainconfigfile, $cfg);
	    }, "update auth server failed");

	return undef;
    }});

# fixme: return format!
__PACKAGE__->register_method ({
    name => 'read', 
    path => '{realm}', 
    method => 'GET',
    description => "Get auth server configuration.",
    parameters => {
   	additionalProperties => 0,
	properties => {
	    realm =>  get_standard_option('realm'),
	},
    },
    returns => {},
    code => sub {
	my ($param) = @_;

	my $cfg = cfs_read_file($domainconfigfile);

	my $realm = $param->{realm};
	
	my $data = $cfg->{$realm};
	die "domain '$realm' does not exist\n" if !$data;

	return $data;
    }});


__PACKAGE__->register_method ({
    name => 'delete', 
    path => '{realm}', 
    method => 'DELETE',
    description => "Delete an authentication server.",
    protected => 1,
    parameters => {
   	additionalProperties => 0,
	properties => {
	    realm =>  get_standard_option('realm'),
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PVE::AccessControl::lock_user_config(
	    sub {

		my $cfg = cfs_read_file($domainconfigfile);

		my $realm = $param->{realm};
	
		die "domain '$realm' does not exist\n" if !$cfg->{$realm};

		delete $cfg->{$realm};

		cfs_write_file($domainconfigfile, $cfg);
	    }, "delete auth server failed");
	
	return undef;
    }});

1;

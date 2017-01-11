package PVE::API2::Domains;

use strict;
use warnings;
use PVE::Tools qw(extract_param);
use PVE::Cluster qw (cfs_read_file cfs_write_file);
use PVE::AccessControl;
use PVE::JSONSchema qw(get_standard_option);

use PVE::SafeSyslog;
use PVE::RESTHandler;
use PVE::Auth::Plugin;

my $domainconfigfile = "domains.cfg";

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index', 
    path => '', 
    method => 'GET',
    description => "Authentication domain index.",
    permissions => { 
	description => "Anyone can access that, because we need that list for the login box (before the user is authenticated).",
	user => 'world', 
    },
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
		tfa => {
		    description => "Two-factor authentication provider.",
		    type => 'string',
		    enum => [ 'yubico', 'oath' ],
		    optional => 1,
		},
		comment => {
		    description => "A comment. The GUI use this text when you select a domain (Realm) on the login window.",
		    type => 'string',
		    optional => 1,
		},
	    },
	},
	links => [ { rel => 'child', href => "{realm}" } ],
    },
    code => sub {
	my ($param) = @_;
    
	my $res = [];

	my $cfg = cfs_read_file($domainconfigfile);
	my $ids = $cfg->{ids};

	foreach my $realm (keys %$ids) {
	    my $d = $ids->{$realm};
	    my $entry = { realm => $realm, type => $d->{type} };
	    $entry->{comment} = $d->{comment} if $d->{comment};
	    $entry->{default} = 1 if $d->{default};
	    if ($d->{tfa} && (my $tfa_cfg = PVE::Auth::Plugin::parse_tfa_config($d->{tfa}))) {
		$entry->{tfa} = $tfa_cfg->{type};
	    }
	    push @$res, $entry;
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'create', 
    protected => 1,
    path => '', 
    method => 'POST',
    permissions => { 
	check => ['perm', '/access/realm', ['Realm.Allocate']],
    },
    description => "Add an authentication server.",
    parameters => PVE::Auth::Plugin->createSchema(),
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PVE::Auth::Plugin::lock_domain_config(
	    sub {
			
		my $cfg = cfs_read_file($domainconfigfile);
		my $ids = $cfg->{ids};

		my $realm = extract_param($param, 'realm');
		my $type = $param->{type};
	
		die "domain '$realm' already exists\n" 
		    if $ids->{$realm};

		die "unable to use reserved name '$realm'\n"
		    if ($realm eq 'pam' || $realm eq 'pve');

		die "unable to create builtin type '$type'\n"
		    if ($type eq 'pam' || $type eq 'pve');

		my $plugin = PVE::Auth::Plugin->lookup($type);
		my $config = $plugin->check_config($realm, $param, 1, 1);

		if ($config->{default}) {
		    foreach my $r (keys %$ids) {
			delete $ids->{$r}->{default};
		    }
		}

		$ids->{$realm} = $config;

		cfs_write_file($domainconfigfile, $cfg);
	    }, "add auth server failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'update', 
    path => '{realm}', 
    method => 'PUT',
    permissions => { 
	check => ['perm', '/access/realm', ['Realm.Allocate']],
    },
    description => "Update authentication server settings.",
    protected => 1,
    parameters => PVE::Auth::Plugin->updateSchema(),
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PVE::Auth::Plugin::lock_domain_config(
	    sub {
			
		my $cfg = cfs_read_file($domainconfigfile);
		my $ids = $cfg->{ids};

		my $digest = extract_param($param, 'digest');
		PVE::SectionConfig::assert_if_modified($cfg, $digest);

		my $realm = extract_param($param, 'realm');

		die "domain '$realm' does not exist\n" 
		    if !$ids->{$realm};

		my $delete_str = extract_param($param, 'delete');
		die "no options specified\n" if !$delete_str && !scalar(keys %$param);

		foreach my $opt (PVE::Tools::split_list($delete_str)) {
		    delete $ids->{$realm}->{$opt};
		}
	
		my $plugin = PVE::Auth::Plugin->lookup($ids->{$realm}->{type});
		my $config = $plugin->check_config($realm, $param, 0, 1);

		if ($config->{default}) {
		    foreach my $r (keys %$ids) {
			delete $ids->{$r}->{default};
		    }
		}

		foreach my $p (keys %$config) {
		    $ids->{$realm}->{$p} = $config->{$p};
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
    permissions => { 
	check => ['perm', '/access/realm', ['Realm.Allocate', 'Sys.Audit'], any => 1],
    },
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
	
	my $data = $cfg->{ids}->{$realm};
	die "domain '$realm' does not exist\n" if !$data;

	$data->{digest} = $cfg->{digest};

	return $data;
    }});


__PACKAGE__->register_method ({
    name => 'delete', 
    path => '{realm}', 
    method => 'DELETE',
    permissions => { 
	check => ['perm', '/access/realm', ['Realm.Allocate']],
    },
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

	PVE::Auth::Plugin::lock_domain_config(
	    sub {

		my $cfg = cfs_read_file($domainconfigfile);
		my $ids = $cfg->{ids};

		my $realm = $param->{realm};
	
		die "domain '$realm' does not exist\n" if !$ids->{$realm};

		delete $ids->{$realm};

		cfs_write_file($domainconfigfile, $cfg);
	    }, "delete auth server failed");
	
	return undef;
    }});

1;

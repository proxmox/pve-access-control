package PVE::API2::User;

use strict;
use warnings;
use PVE::Cluster qw (cfs_read_file cfs_write_file);
use PVE::Tools qw(split_list);
use PVE::AccessControl;
use PVE::JSONSchema qw(get_standard_option);

use PVE::SafeSyslog;

use Data::Dumper; # fixme: remove

use PVE::RESTHandler;

use base qw(PVE::RESTHandler);

my $extract_user_data = sub {
    my ($data, $full) = @_;

    my $res = {};

    foreach my $prop (qw(enable expire firstname lastname email comment)) {
	$res->{$prop} = $data->{$prop} if defined($data->{$prop});
    }

    return $res if !$full;

    $res->{groups} = $data->{groups} ? [ keys %{$data->{groups}} ] : [];

    return $res;
};

__PACKAGE__->register_method ({
    name => 'index', 
    path => '', 
    method => 'GET',
    description => "User index.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    enabled => {
		type => 'boolean',
		description => "Optional filter for enable property.",
		optional => 1,
	    }
	},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		userid => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{userid}" } ],
    },
    code => sub {
	my ($param) = @_;
    
	my $res = [];

	my $usercfg = cfs_read_file("user.cfg");
 
	foreach my $user (keys %{$usercfg->{users}}) {
	    next if $user eq 'root';
	    
	    my $entry = &$extract_user_data($usercfg->{users}->{$user});

	    if (defined($param->{enabled})) {
		next if $entry->{enable} && !$param->{enabled};
		next if !$entry->{enable} && $param->{enabled};
	    }

	    $entry->{userid} = $user;
	    push @$res, $entry;
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'create_user', 
    protected => 1,
    path => '', 
    method => 'POST',
    description => "Create new user.",
    parameters => {
   	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	    password => { type => 'string', optional => 1 },
	    groups => { type => 'string', optional => 1, format => 'pve-groupid-list'},
	    firstname => { type => 'string', optional => 1 },
	    lastname => { type => 'string', optional => 1 },
	    email => { type => 'string', optional => 1, format => 'email-opt' },
	    comment => { type => 'string', optional => 1 },
	    expire => { 
		description => "Account expiration date (seconds since epoch). '0' means no expiration date.",
		type => 'integer', 
		minimum => 0,
		optional => 1,
	    },
	    enable => {
		description => "Enable the account (default). You can set this to '0' to disable the accout",
		type => 'boolean',
		optional => 1,
		default => 1,
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PVE::AccessControl::lock_user_config(
	    sub {
			
		my ($username, $ruid, $realm) = PVE::AccessControl::verify_username($param->{userid});
	
		my $usercfg = cfs_read_file("user.cfg");

		die "user '$username' already exists\n" 
		    if $usercfg->{users}->{$username};
			 
		PVE::AccessControl::domain_set_password($realm, $ruid, $param->{password})
		    if $param->{password};

		my $enable = defined($param->{enable}) ? $param->{enable} : 1;
		$usercfg->{users}->{$username} = { enable => $enable };
		$usercfg->{users}->{$username}->{expire} = $param->{expire} if $param->{expire};

		if ($param->{groups}) {
		    foreach my $group (split_list($param->{groups})) {
			if ($usercfg->{groups}->{$group}) {
			    PVE::AccessControl::add_user_group($username, $usercfg, $group);
			} else {
			    die "no such group '$group'\n";
			}
		    }
		}

		$usercfg->{users}->{$username}->{firstname} = $param->{firstname} if $param->{firstname};
		$usercfg->{users}->{$username}->{lastname} = $param->{lastname} if $param->{lastname};
		$usercfg->{users}->{$username}->{email} = $param->{email} if $param->{email};
		$usercfg->{users}->{$username}->{comment} = $param->{comment} if $param->{comment};

		cfs_write_file("user.cfg", $usercfg);
	    }, "create user failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'read_user', 
    path => '{userid}', 
    method => 'GET',
    description => "Get user configuration.",
    parameters => {
   	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	},
    },
    returns => {
   	additionalProperties => 0,
	properties => {
	    enable => { type => 'boolean' },
	    expire => { type => 'integer', optional => 1 },
	    firstname => { type => 'string', optional => 1 },
	    lastname => { type => 'string', optional => 1 },
	    email => { type => 'string', optional => 1 },
	    comment => { type => 'string', optional => 1 },    
	    groups => { type => 'array' },
	}
    },
    code => sub {
	my ($param) = @_;

	my ($username, undef, $domain) = 
	    PVE::AccessControl::verify_username($param->{userid});

	my $usercfg = cfs_read_file("user.cfg");
 
	my $data = $usercfg->{users}->{$username};

	die "user '$username' does not exist\n" if !$data;

	return &$extract_user_data($data, 1);
    }});

__PACKAGE__->register_method ({
    name => 'update_user', 
    protected => 1,
    path => '{userid}', 
    method => 'PUT',
    description => "Update user configuration.",
    parameters => {
   	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	    password => { type => 'string', optional => 1 },
	    groups => { type => 'string', optional => 1,  format => 'pve-groupid-list'  },
	    append => { 
		type => 'boolean', 
		optional => 1,
		requires => 'groups',
	    },
	    enable => {
		description => "Enable/disable the account.",
		type => 'boolean',
		optional => 1,
	    },
	    firstname => { type => 'string', optional => 1 },
	    lastname => { type => 'string', optional => 1 },
	    email => { type => 'string', optional => 1, format => 'email-opt' },
	    comment => { type => 'string', optional => 1 },
	    expire => { 
		description => "Account expiration date (seconds since epoch). '0' means no expiration date.",
		type => 'integer', 
		minimum => 0,
		optional => 1 
	    },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;
	
	PVE::AccessControl::lock_user_config(
	    sub {

		my ($username, $ruid, $realm) = 
		    PVE::AccessControl::verify_username($param->{userid});
	
		my $usercfg = cfs_read_file("user.cfg");

		die "user '$username' does not exist\n" 
		    if !$usercfg->{users}->{$username};

		PVE::AccessControl::domain_set_password($realm, $ruid, $param->{password})
		    if $param->{password};

		$usercfg->{users}->{$username}->{enable} = $param->{enable} if defined($param->{enable});

		$usercfg->{users}->{$username}->{expire} = $param->{expire} if defined($param->{expire});

		PVE::AccessControl::delete_user_group($username, $usercfg) 
		    if (!$param->{append} && $param->{groups});

		if ($param->{groups}) {
		    foreach my $group (split_list($param->{groups})) {
			if ($usercfg->{groups}->{$group}) {
			    PVE::AccessControl::add_user_group($username, $usercfg, $group);
			} else {
			    die "no such group '$group'\n";
			}
		    }
		}

		$usercfg->{users}->{$username}->{firstname} = $param->{firstname} if defined($param->{firstname});
		$usercfg->{users}->{$username}->{lastname} = $param->{lastname} if defined($param->{lastname});
		$usercfg->{users}->{$username}->{email} = $param->{email} if defined($param->{email});
		$usercfg->{users}->{$username}->{comment} = $param->{comment} if defined($param->{comment});

		cfs_write_file("user.cfg", $usercfg);
	    }, "update user failed");
	
	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'delete_user', 
    protected => 1,
    path => '{userid}', 
    method => 'DELETE',
    description => "Delete user.",
    parameters => {
   	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PVE::AccessControl::lock_user_config(
	    sub {

		my ($username, $ruid, $realm) = 
		    PVE::AccessControl::verify_username($param->{userid});

		my $usercfg = cfs_read_file("user.cfg");

		die "user '$username' does not exist\n" 
		    if !$usercfg->{users}->{$username};

		delete ($usercfg->{users}->{$username});

		PVE::AccessControl::delete_shadow_password($ruid) if $realm eq 'pve';
		PVE::AccessControl::delete_user_group($username, $usercfg);
		PVE::AccessControl::delete_user_acl($username, $usercfg);

		cfs_write_file("user.cfg", $usercfg);
	    }, "delete user failed");
	
	return undef;
    }});

1;

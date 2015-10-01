package PVE::API2::Group;

use strict;
use warnings;
use PVE::Cluster qw (cfs_read_file cfs_write_file);
use PVE::AccessControl;
use PVE::SafeSyslog;
use PVE::RESTHandler;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    name => 'index', 
    path => '', 
    method => 'GET',
    description => "Group index.",
    permissions => { 
	description => "The returned list is restricted to groups where you have 'User.Modify', 'Sys.Audit'  or 'Group.Allocate' permissions on /access/groups/<group>.",
	user => 'all',
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
		groupid => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{groupid}" } ],
    },
    code => sub {
	my ($param) = @_;
    
	my $res = [];

	my $rpcenv = PVE::RPCEnvironment::get();
	my $usercfg = cfs_read_file("user.cfg");
	my $authuser = $rpcenv->get_user();

	my $privs = [ 'User.Modify', 'Sys.Audit', 'Group.Allocate'];

	foreach my $group (keys %{$usercfg->{groups}}) {
	    next if !$rpcenv->check_any($authuser, "/access/groups/$group", $privs, 1);
	    my $data = $usercfg->{groups}->{$group};
	    my $entry = { groupid => $group };
	    $entry->{comment} = $data->{comment} if defined($data->{comment});
	    push @$res, $entry;
	}

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'create_group', 
    protected => 1,
    path => '', 
    method => 'POST',
    permissions => { 
	check => ['perm', '/access/groups', ['Group.Allocate']],
    },
    description => "Create new group.",
    parameters => {
   	additionalProperties => 0,
	properties => {
	    groupid => { type => 'string', format => 'pve-groupid' },
	    comment => { type => 'string', optional => 1 },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PVE::AccessControl::lock_user_config(
	    sub {
			
		my $usercfg = cfs_read_file("user.cfg");

		my $group = $param->{groupid};
	
		die "group '$group' already exists\n" 
		    if $usercfg->{groups}->{$group};

		$usercfg->{groups}->{$group} = { users => {} };

		$usercfg->{groups}->{$group}->{comment} = $param->{comment} if $param->{comment};

		
		cfs_write_file("user.cfg", $usercfg);
	    }, "create group failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'update_group', 
    protected => 1,
    path => '{groupid}', 
    method => 'PUT',
    permissions => { 
	check => ['perm', '/access/groups', ['Group.Allocate']],
    },
    description => "Update group data.",
    parameters => {
   	additionalProperties => 0,
	properties => {
	    groupid => {
		type => 'string', format => 'pve-groupid',
		completion => \&PVE::AccessControl::complete_group,
	    },
	    comment => { type => 'string', optional => 1 },
	},
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PVE::AccessControl::lock_user_config(
	    sub {
			
		my $usercfg = cfs_read_file("user.cfg");

		my $group = $param->{groupid};
	
		my $data = $usercfg->{groups}->{$group};

		die "group '$group' does not exist\n" 
		    if !$data;

		$data->{comment} = $param->{comment} if defined($param->{comment});
		
		cfs_write_file("user.cfg", $usercfg);
	    }, "update group failed");

	return undef;
    }});

__PACKAGE__->register_method ({
    name => 'read_group', 
    path => '{groupid}', 
    method => 'GET',
    permissions => { 
	check => ['perm', '/access/groups', ['Sys.Audit', 'Group.Allocate'], any => 1],
   },
    description => "Get group configuration.",
    parameters => {
   	additionalProperties => 0,
	properties => {
	    groupid => { type => 'string', format => 'pve-groupid' },
	},
    },
    returns => {
	type => "object",
	additionalProperties => 0,
	properties => {
	    comment => { type => 'string', optional => 1 },
	    members => {
		type => 'array',
		items => {
		    type => "string",
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $group = $param->{groupid};

	my $usercfg = cfs_read_file("user.cfg");
 
	my $data = $usercfg->{groups}->{$group};

	die "group '$group' does not exist\n" if !$data;

	my $members = $data->{users} ? [ keys %{$data->{users}} ] : [];

	my $res = { members => $members };

	$res->{comment} = $data->{comment} if defined($data->{comment});

	return $res;
    }});


__PACKAGE__->register_method ({
    name => 'delete_group', 
    protected => 1,
    path => '{groupid}', 
    method => 'DELETE',
    permissions => { 
	check => ['perm', '/access/groups', ['Group.Allocate']],
    },
    description => "Delete group.",
    parameters => {
   	additionalProperties => 0,
	properties => {
	    groupid => {
		type => 'string' , format => 'pve-groupid',
		completion => \&PVE::AccessControl::complete_group,
	    },
	}
    },
    returns => { type => 'null' },
    code => sub {
	my ($param) = @_;

	PVE::AccessControl::lock_user_config(
	    sub {

		my $usercfg = cfs_read_file("user.cfg");

		my $group = $param->{groupid};

		die "group '$group' does not exist\n" 
		    if !$usercfg->{groups}->{$group};
	
		delete ($usercfg->{groups}->{$group});

		PVE::AccessControl::delete_group_acl($group, $usercfg);

		cfs_write_file("user.cfg", $usercfg);
	    }, "delete group failed");
	
	return undef;
    }});

1;

package PVE::API2::AccessControl;

use strict;
use warnings;

use PVE::SafeSyslog;
use PVE::RPCEnvironment;
use PVE::Cluster qw(cfs_read_file);
use PVE::RESTHandler;
use PVE::AccessControl;
use PVE::JSONSchema qw(get_standard_option);
use PVE::API2::Domains;
use PVE::API2::User;
use PVE::API2::Group;
use PVE::API2::Role;
use PVE::API2::ACL;

use base qw(PVE::RESTHandler);

__PACKAGE__->register_method ({
    subclass => "PVE::API2::User",  
    path => 'users',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Group",  
    path => 'groups',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Role",  
    path => 'roles',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::ACL",  
    path => 'acl',
});

__PACKAGE__->register_method ({
    subclass => "PVE::API2::Domains",  
    path => 'domains',
});

__PACKAGE__->register_method ({
    name => 'index', 
    path => '', 
    method => 'GET',
    description => "Directory index.",
    parameters => {
    	additionalProperties => 0,
	properties => {},
    },
    returns => {
	type => 'array',
	items => {
	    type => "object",
	    properties => {
		subdir => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;
    
	my $res = [];

	my $ma = __PACKAGE__->method_attributes();

	foreach my $info (@$ma) {
	    next if !$info->{subclass};

	    my $subpath = $info->{match_re}->[0];

	    push @$res, { subdir => $subpath };
	}

	push @$res, { subdir => 'ticket' };

	return $res;
    }});

__PACKAGE__->register_method ({
    name => 'create_ticket', 
    path => 'ticket', 
    method => 'POST',
    permissions => { user => 'world' },
    protected => 1, # else we can't access shadow files
    description => "Create authentication ticket.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    username => {
		description => "User name",
		type => 'string',
		maxLength => 64,
	    },
	    realm =>  get_standard_option('realm', {
		description => "You can optionally pass the realm using this parameter. Normally the realm is simply added to the username <username>\@<relam>.",
		optional => 1}),
	    password => { 
		description => "The secret password. This can also be a valid ticket.",
		type => 'string',
	    },
	    path => {
		description => "Only create ticket if user have access 'privs' on 'path'",
		type => 'string',
		requires => 'privs',
		optional => 1,
		maxLength => 64,
	    },
	    privs => { 
		description => "Only create ticket if user have access 'privs' on 'path'",
		type => 'string' , format => 'pve-priv-list',
		requires => 'path',
		optional => 1,
		maxLength => 64,
	    },
	}
    },
    returns => {
	type => "object",
	properties => {
	    ticket => { type => 'string' },
	    username => { type => 'string' },
	    CSRFPreventionToken => { type => 'string' },
	}
    },
    code => sub {
	my ($param) = @_;
    
	my $username = $param->{username};
	$username .= "\@$param->{realm}" if $param->{realm};

	my $rpcenv = PVE::RPCEnvironment::get();
	my $clientip = $rpcenv->get_client_ip() || '';

	my $ticket;
	my $token;
	eval {

	    # test if user exists and is enabled
	    $rpcenv->check_user_enabled($username);

	    if ($param->{path} && $param->{privs}) {
		my $privs = [ PVE::Tools::split_list($param->{privs}) ];
		my $path = PVE::AccessControl::normalize_path($param->{path});
		if (!($path && scalar(@$privs) && $rpcenv->check($username, $path, $privs))) {
		    die "no permission ($param->{path}, $param->{privs})\n";
		}
	    }

	    my $tmp;
	    if (($tmp = PVE::AccessControl::verify_ticket($param->{password}, 1)) &&
		($tmp eq 'root@pam' || $tmp eq $username)) {
		# got valid ticket
		# Note: root@pam can create tickets for other users
		
	    } else {
		$username = PVE::AccessControl::authenticate_user($username, $param->{password});
	    }
	    $ticket = PVE::AccessControl::assemble_ticket($username);
	    $token = PVE::AccessControl::assemble_csrf_prevention_token($username);
	};
	if (my $err = $@) {
	    syslog('err', "authentication failure; rhost=$clientip user=$username msg=$err");
	    die $err;
	}

	PVE::Cluster::log_msg('info', 'root@pam', "successful auth for user '$username'");

	return {
	    ticket => $ticket,
	    username => $username,
	    CSRFPreventionToken => $token,
	};
    }});

1;

package PVE::Auth::OpenId;

use strict;
use warnings;

use PVE::Tools;
use PVE::Auth::Plugin;
use PVE::Cluster qw(cfs_register_file cfs_read_file cfs_write_file cfs_lock_file);

use base qw(PVE::Auth::Plugin);

sub type {
    return 'openid';
}

sub properties {
    return {
	"issuer-url" => {
	    description => "OpenID Issuer Url",
	    type => 'string',
	    maxLength => 256,
	},
	"client-id" => {
	    description => "OpenID Client ID",
	    type => 'string',
	    maxLength => 256,
	},
	"client-key" => {
	    description => "OpenID Client Key",
	    type => 'string',
	    optional => 1,
	    maxLength => 256,
	},
	autocreate => {
	    description => "Automatically create users if they do not exist.",
	    optional => 1,
	    type => 'boolean',
	    default => 0,
	},
	"username-claim" => {
	    description => "OpenID claim used to generate the unique username.",
	    type => 'string',
	    optional => 1,
	},
	prompt => {
	    description => "Specifies whether the Authorization Server prompts the End-User for"
	        ." reauthentication and consent.",
	    type => 'string',
	    pattern => '(?:none|login|consent|select_account|\S+)', # \S+ is the extension variant
	    optional => 1,
	},
	scopes => {
	    description => "Specifies the scopes (user details) that should be authorized and"
	        ." returned, for example 'email' or 'profile'.",
	    type => 'string', # format => 'some-safe-id-list', # FIXME: TODO
	    default => "email profile",
	    optional => 1,
	},
   };
}

sub options {
    return {
	"issuer-url" => {},
	"client-id" => {},
	"client-key" => { optional => 1 },
	autocreate => { optional => 1 },
	"username-claim" => { optional => 1, fixed => 1 },
	prompt => { optional => 1 },
	scopes => { optional => 1 },
	default => { optional => 1 },
	comment => { optional => 1 },
    };
}

sub authenticate_user {
    my ($class, $config, $realm, $username, $password) = @_;

    die "OpenID realm does not allow password verification.\n";
}


1;

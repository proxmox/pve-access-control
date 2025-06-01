package PVE::Auth::OpenId;

use strict;
use warnings;

use PVE::Tools;
use PVE::Auth::Plugin;
use PVE::Cluster qw(cfs_register_file cfs_read_file cfs_write_file cfs_lock_file);

use base qw(PVE::Auth::Plugin);

# FIXME: restrict username-claim as well?
my $openid_claim_regex = qr/[A-Za-z0-9\.\-_]+/;

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
        "groups-claim" => {
            description => "OpenID claim used to retrieve groups with.",
            type => 'string',
            pattern => $openid_claim_regex,
            maxLength => 256,
            optional => 1,
        },
        "groups-autocreate" => {
            description => "Automatically create groups if they do not exist.",
            optional => 1,
            type => 'boolean',
            default => 0,
        },
        "groups-overwrite" => {
            description => "All groups will be overwritten for the user on login.",
            type => 'boolean',
            default => 0,
            optional => 1,
        },
        prompt => {
            description => "Specifies whether the Authorization Server prompts the End-User for"
                . " reauthentication and consent.",
            type => 'string',
            pattern => '(?:none|login|consent|select_account|\S+)', # \S+ is the extension variant
            optional => 1,
        },
        scopes => {
            description => "Specifies the scopes (user details) that should be authorized and"
                . " returned, for example 'email' or 'profile'.",
            type => 'string', # format => 'some-safe-id-list', # FIXME: TODO
            default => "email profile",
            optional => 1,
        },
        'acr-values' => {
            description =>
                "Specifies the Authentication Context Class Reference values that the"
                . "Authorization Server is being requested to use for the Auth Request.",
            type => 'string',
            pattern => '^[^\x00-\x1F\x7F <>#"]*$', # Prohibit characters not allowed in URI RFC 2396.
            optional => 1,
        },
        "query-userinfo" => {
            description => "Enables querying the userinfo endpoint for claims values.",
            type => 'boolean',
            default => 1,
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
        "groups-claim" => { optional => 1 },
        "groups-autocreate" => { optional => 1 },
        "groups-overwrite" => { optional => 1 },
        prompt => { optional => 1 },
        scopes => { optional => 1 },
        "acr-values" => { optional => 1 },
        default => { optional => 1 },
        comment => { optional => 1 },
        "query-userinfo" => { optional => 1 },
    };
}

sub authenticate_user {
    my ($class, $config, $realm, $username, $password) = @_;

    die "OpenID realm does not allow password verification.\n";
}

1;

package PVE::API2::OpenId;

use strict;
use warnings;

use PVE::Tools qw(extract_param);
use PVE::RS::OpenId;

use PVE::Exception qw(raise raise_perm_exc raise_param_exc);
use PVE::SafeSyslog;
use PVE::RPCEnvironment;
use PVE::Cluster qw(cfs_read_file cfs_write_file);
use PVE::AccessControl;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Auth::Plugin;
use PVE::Auth::OpenId;

use PVE::RESTHandler;

use base qw(PVE::RESTHandler);

my $openid_state_path = "/var/lib/pve-manager";

my $lookup_openid_auth = sub {
    my ($realm, $redirect_url) = @_;

    my $cfg = cfs_read_file('domains.cfg');
    my $ids = $cfg->{ids};

    die "authentication domain '$realm' does not exist\n" if !$ids->{$realm};

    my $config = $ids->{$realm};
    die "wrong realm type ($config->{type} != openid)\n" if $config->{type} ne "openid";

    my $openid_config = {
	issuer_url => $config->{'issuer-url'},
	client_id => $config->{'client-id'},
	client_key => $config->{'client-key'},
    };
    $openid_config->{prompt} = $config->{'prompt'} if defined($config->{'prompt'});

    my $scopes = $config->{'scopes'} // 'email profile';
    $openid_config->{scopes} = [ PVE::Tools::split_list($scopes) ];

    if (defined(my $acr = $config->{'acr-values'})) {
	$openid_config->{acr_values} = [ PVE::Tools::split_list($acr) ];
    }

    my $openid = PVE::RS::OpenId->discover($openid_config, $redirect_url);
    return ($config, $openid);
};

__PACKAGE__->register_method ({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Directory index.",
    permissions => {
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
		subdir => { type => 'string' },
	    },
	},
	links => [ { rel => 'child', href => "{subdir}" } ],
    },
    code => sub {
	my ($param) = @_;

	return [
	    { subdir => 'auth-url' },
	    { subdir => 'login' },
	];
    }});

__PACKAGE__->register_method ({
    name => 'auth_url',
    path => 'auth-url',
    method => 'POST',
    protected => 1,
    description => "Get the OpenId Authorization Url for the specified realm.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    realm => get_standard_option('realm'),
	    'redirect-url' => {
		description => "Redirection Url. The client should set this to the used server url (location.origin).",
		type => 'string',
		maxLength => 255,
	    },
	},
    },
    returns => {
	type => "string",
	description => "Redirection URL.",
    },
    permissions => { user => 'world' },
    code => sub {
	my ($param) = @_;

	my $dcconf = PVE::Cluster::cfs_read_file('datacenter.cfg');
	local $ENV{all_proxy} = $dcconf->{http_proxy} if exists $dcconf->{http_proxy};

	my $realm = extract_param($param, 'realm');
	my $redirect_url = extract_param($param, 'redirect-url');

	my ($config, $openid) = $lookup_openid_auth->($realm, $redirect_url);
	my $url = $openid->authorize_url($openid_state_path , $realm);

	return $url;
    }});

__PACKAGE__->register_method ({
    name => 'login',
    path => 'login',
    method => 'POST',
    protected => 1,
    description => " Verify OpenID authorization code and create a ticket.",
    parameters => {
	additionalProperties => 0,
	properties => {
	    'state' => {
		description => "OpenId state.",
		type => 'string',
		maxLength => 1024,
            },
	    code => {
		description => "OpenId authorization code.",
		type => 'string',
		maxLength => 4096,
            },
	    'redirect-url' => {
		description => "Redirection Url. The client should set this to the used server url (location.origin).",
		type => 'string',
		maxLength => 255,
	    },
	},
    },
    returns => {
	properties => {
	    username => { type => 'string' },
	    ticket => { type => 'string' },
	    CSRFPreventionToken => { type => 'string' },
	    cap => { type => 'object' },  # computed api permissions
	    clustername => { type => 'string', optional => 1 },
	},
    },
    permissions => { user => 'world' },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();

	my $res;
	eval {
	    my $dcconf = PVE::Cluster::cfs_read_file('datacenter.cfg');
	    local $ENV{all_proxy} = $dcconf->{http_proxy} if exists $dcconf->{http_proxy};

	    my ($realm, $private_auth_state) = PVE::RS::OpenId::verify_public_auth_state(
		$openid_state_path, $param->{'state'});

	    my $redirect_url = extract_param($param, 'redirect-url');

	    my ($config, $openid) = $lookup_openid_auth->($realm, $redirect_url);

	    my $info = $openid->verify_authorization_code(
		$param->{code},
		$private_auth_state,
		$config->{'query-userinfo'} // 1,
	    );
	    my $subject = $info->{'sub'};

	    my $unique_name;

	    my $user_attr = $config->{'username-claim'} // 'sub';
	    if (defined($info->{$user_attr})) {
		$unique_name = $info->{$user_attr};
	    } elsif ($user_attr eq 'subject') { # stay compat with old versions
		$unique_name = $subject;
	    } elsif ($user_attr eq 'username') { # stay compat with old versions
		my $username = $info->{'preferred_username'};
		die "missing claim 'preferred_username'\n" if !defined($username);
		$unique_name =  $username;
	    } else {
		# neither the attr nor fallback are defined in info..
		die "missing configured claim '$user_attr' in returned info object\n";
	    }

	    my $username = "${unique_name}\@${realm}";

	    # first, check if $username respects our naming conventions
	    PVE::Auth::Plugin::verify_username($username);

	    if ($config->{'autocreate'} && !$rpcenv->check_user_exist($username, 1)) {
		PVE::AccessControl::lock_user_config(sub {
		    my $usercfg = cfs_read_file("user.cfg");

		    die "user '$username' already exists\n" if $usercfg->{users}->{$username};

		    my $entry = { enable => 1 };
		    if (defined(my $email = $info->{'email'})) {
			$entry->{email} = $email;
		    }
		    if (defined(my $given_name = $info->{'given_name'})) {
			$entry->{firstname} = $given_name;
		    }
		    if (defined(my $family_name = $info->{'family_name'})) {
			$entry->{lastname} = $family_name;
		    }

		    $usercfg->{users}->{$username} = $entry;

		    cfs_write_file("user.cfg", $usercfg);
		}, "autocreate openid user failed");
	    } else {
		# test if user exists and is enabled
		$rpcenv->check_user_enabled($username);
	    }

	    if (defined(my $groups_claim = $config->{'groups-claim'})) {
		if (defined(my $groups_list = $info->{$groups_claim})) {
		    if (ref($groups_list) eq 'ARRAY') {
			PVE::AccessControl::lock_user_config(sub {
			    my $usercfg = cfs_read_file("user.cfg");

			    my $oidc_groups;
			    for my $group (@$groups_list) {
				if (PVE::AccessControl::verify_groupname($group, 1)) {
				    # add realm name as suffix to group
				    $oidc_groups->{"$group-$realm"} = 1;
				} else {
				    # ignore any groups in the list that have invalid characters
				    syslog(
					'warn',
					"openid group '$group' contains invalid characters"
				    );
				}
			    }

			    # get groups that exist in OIDC and PVE
			    my $groups_intersect;
			    for my $group (keys %$oidc_groups) {
				$groups_intersect->{$group} = 1 if $usercfg->{groups}->{$group};
			    }

			    if ($config->{'groups-autocreate'}) {
				# populate all groups in claim
				$groups_intersect = $oidc_groups;
				my $groups_to_create;
				for my $group (keys %$oidc_groups) {
				    $groups_to_create->{$group} = 1 if !$usercfg->{groups}->{$group};
				}
				if ($groups_to_create) {
				    # log a messages about created groups here
				    my $groups_to_create_string = join(', ', sort keys %$groups_to_create);
				    syslog(
					'info',
					"groups created automatically from openid claim: $groups_to_create_string"
				    );
				}
			    }

			    # if groups should be overwritten, delete all the users groups first
			    if ($config->{'groups-overwrite'} ) {
				PVE::AccessControl::delete_user_group(
				    $username,
				    $usercfg,
				);
				syslog(
				    'info',
				    "openid overwrite groups enabled; user '$username' removed from all groups"
				);
			    }

			    if (keys %$groups_intersect) {
				# ensure user is a member of the groups
				for my $group (keys %$groups_intersect) {
				    PVE::AccessControl::add_user_group(
					$username,
					$usercfg,
					$group
				    );
				}

				my $groups_intersect_string = join(', ', sort keys %$groups_intersect);
				syslog(
				    'info',
				    "openid user '$username' added to groups: $groups_intersect_string"
				);
			    }

			    cfs_write_file("user.cfg", $usercfg);
			}, "openid group mapping failed");
		    } else {
			syslog('err', "openid groups list is not an array; groups will not be updated");
		    }
		} else {
		    syslog('err', "openid groups claim '$groups_claim' is not found in claims");
		}
	    }

	    my $ticket = PVE::AccessControl::assemble_ticket($username);
	    my $csrftoken = PVE::AccessControl::assemble_csrf_prevention_token($username);
	    my $cap = $rpcenv->compute_api_permission($username);

	    $res = {
		ticket => $ticket,
		username => $username,
		CSRFPreventionToken => $csrftoken,
		cap => $cap,
	    };

	    my $clinfo = PVE::Cluster::get_clinfo();
	    if ($clinfo->{cluster}->{name} && $rpcenv->check($username, '/', ['Sys.Audit'], 1)) {
		$res->{clustername} = $clinfo->{cluster}->{name};
	    }
	};
	if (my $err = $@) {
	    my $clientip = $rpcenv->get_client_ip() || '';
	    syslog('err', "openid authentication failure; rhost=$clientip msg=$err");
	    # do not return any info to prevent user enumeration attacks
	    die PVE::Exception->new("authentication failure\n", code => 401);
	}

	PVE::Cluster::log_msg('info', 'root@pam', "successful openid auth for user '$res->{username}'");

	return $res;
    }});

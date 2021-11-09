package PVE::API2::TFA;

use strict;
use warnings;

use PVE::AccessControl;
use PVE::Cluster qw(cfs_read_file);
use PVE::JSONSchema qw(get_standard_option);
use PVE::Exception qw(raise raise_perm_exc raise_param_exc);
use PVE::RPCEnvironment;

use PVE::API2::AccessControl; # for old login api get_u2f_instance method

use PVE::RESTHandler;

use base qw(PVE::RESTHandler);

### OLD API

__PACKAGE__->register_method({
    name => 'verify_tfa',
    path => '',
    method => 'POST',
    permissions => { user => 'all' },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to access TFA information
    description => 'Finish a u2f challenge.',
    parameters => {
	additionalProperties => 0,
	properties => {
	    response => {
		type => 'string',
		description => 'The response to the current authentication challenge.',
	    },
	}
    },
    returns => {
	type => 'object',
	properties => {
	    ticket => { type => 'string' },
	    # cap
	}
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();
	my ($username, undef, $realm) = PVE::AccessControl::verify_username($authuser);

	my ($tfa_type, $tfa_data) = PVE::AccessControl::user_get_tfa($username, $realm, 0);
	if (!defined($tfa_type)) {
	    raise('no u2f data available');
	}

	eval {
	    if ($tfa_type eq 'u2f') {
		my $challenge = $rpcenv->get_u2f_challenge()
		   or raise('no active challenge');

		my $keyHandle = $tfa_data->{keyHandle};
		my $publicKey = $tfa_data->{publicKey};
		raise("incomplete u2f setup")
		    if !defined($keyHandle) || !defined($publicKey);

		my $u2f = PVE::API2::AccessControl::get_u2f_instance($rpcenv, $publicKey, $keyHandle);
		$u2f->set_challenge($challenge);

		my ($counter, $present) = $u2f->auth_verify($param->{response});
		# Do we want to do anything with these?
	    } else {
		# sanity check before handing off to the verification code:
		my $keys = $tfa_data->{keys} or die "missing tfa keys\n";
		my $config = $tfa_data->{config} or die "bad tfa entry\n";
		PVE::AccessControl::verify_one_time_pw($tfa_type, $authuser, $keys, $config, $param->{response});
	    }
	};
	if (my $err = $@) {
	    my $clientip = $rpcenv->get_client_ip() || '';
	    syslog('err', "authentication verification failure; rhost=$clientip user=$authuser msg=$err");
	    die PVE::Exception->new("authentication failure\n", code => 401);
	}

	return {
	    ticket => PVE::AccessControl::assemble_ticket($authuser),
	    cap => $rpcenv->compute_api_permission($authuser),
	}
    }});

### END OLD API

my $TFA_TYPE_SCHEMA = {
    type => 'string',
    description => 'TFA Entry Type.',
    enum => [qw(totp u2f webauthn recovery yubico)],
};

my %TFA_INFO_PROPERTIES = (
    id => {
	type => 'string',
	description => 'The id used to reference this entry.',
    },
    description => {
	type => 'string',
	description => 'User chosen description for this entry.',
    },
    created => {
	type => 'integer',
	description => 'Creation time of this entry as unix epoch.',
    },
    enable => {
	type => 'boolean',
	description => 'Whether this TFA entry is currently enabled.',
	optional => 1,
	default => 1,
    },
);

my $TYPED_TFA_ENTRY_SCHEMA = {
    type => 'object',
    description => 'TFA Entry.',
    properties => {
	type => $TFA_TYPE_SCHEMA,
	%TFA_INFO_PROPERTIES,
    },
};

my $TFA_ID_SCHEMA = {
    type => 'string',
    description => 'A TFA entry id.',
};

__PACKAGE__->register_method ({
    name => 'list_user_tfa',
    path => '{userid}',
    method => 'GET',
    permissions => {
	check => [ 'or',
	    ['userid-param', 'self'],
	    ['userid-group', ['User.Modify', 'Sys.Audit']],
	],
    },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to change the regular user's TFA settings
    description => 'List TFA configurations of users.',
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid', {
		completion => \&PVE::AccessControl::complete_username,
	    }),
	}
    },
    returns => {
	description => "A list of the user's TFA entries.",
	type => 'array',
	items => $TYPED_TFA_ENTRY_SCHEMA,
    },
    code => sub {
	my ($param) = @_;
	my $tfa_cfg = cfs_read_file('priv/tfa.cfg');
	return $tfa_cfg->api_list_user_tfa($param->{userid});
    }});

__PACKAGE__->register_method ({
    name => 'get_tfa_entry',
    path => '{userid}/{id}',
    method => 'GET',
    permissions => {
	check => [ 'or',
	    ['userid-param', 'self'],
	    ['userid-group', ['User.Modify', 'Sys.Audit']],
	],
    },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to change the regular user's TFA settings
    description => 'A requested TFA entry if present.',
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid', {
		completion => \&PVE::AccessControl::complete_username,
	    }),
	    id => $TFA_ID_SCHEMA,
	}
    },
    returns => $TYPED_TFA_ENTRY_SCHEMA,
    code => sub {
	my ($param) = @_;
	my $tfa_cfg = cfs_read_file('priv/tfa.cfg');
	return $tfa_cfg->api_get_tfa_entry($param->{userid}, $param->{id});
    }});

__PACKAGE__->register_method ({
    name => 'list_tfa',
    path => '',
    method => 'GET',
    permissions => {
	description => "Returns all or just the logged-in user, depending on privileges.",
	user => 'all',
    },
    protected => 1, # else we can't access shadow files
    allowtoken => 0, # we don't want tokens to change the regular user's TFA settings
    description => 'List TFA configurations of users.',
    parameters => {
	additionalProperties => 0,
	properties => {}
    },
    returns => {
	description => "The list tuples of user and TFA entries.",
	type => 'array',
	items => {
	    type => 'object',
	    properties => {
		userid => {
		    type => 'string',
		    description => 'User this entry belongs to.',
		},
		entries => {
		    type => 'array',
		    items => $TYPED_TFA_ENTRY_SCHEMA,
		},
	    },
	},
    },
    code => sub {
	my ($param) = @_;

	my $rpcenv = PVE::RPCEnvironment::get();
	my $authuser = $rpcenv->get_user();


	my $top_level_allowed = ($authuser eq 'root@pam');

	my $tfa_cfg = cfs_read_file('priv/tfa.cfg');
	return $tfa_cfg->api_list_tfa($authuser, $top_level_allowed);
    }});

1;

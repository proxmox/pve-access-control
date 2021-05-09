package PVE::CLI::pveum;

use strict;
use warnings;

use PVE::AccessControl;
use PVE::RPCEnvironment;
use PVE::API2::User;
use PVE::API2::Group;
use PVE::API2::Role;
use PVE::API2::ACL;
use PVE::API2::AccessControl;
use PVE::API2::Domains;
use PVE::CLIFormatter;
use PVE::CLIHandler;
use PVE::JSONSchema qw(get_standard_option);
use PVE::PTY;
use PVE::RESTHandler;
use PVE::Tools qw(extract_param);

use base qw(PVE::CLIHandler);

sub setup_environment {
    PVE::RPCEnvironment->setup_default_cli_env();
}

sub param_mapping {
    my ($name) = @_;

    my $mapping = {
	'change_password' => [
	    PVE::CLIHandler::get_standard_mapping('pve-password'),
	],
	'create_ticket' => [
	    PVE::CLIHandler::get_standard_mapping('pve-password', {
		func => sub {
		    # do not accept values given on cmdline
		    return PVE::PTY::read_password('Enter password: ');
		},
	    }),
	]
    };

    return $mapping->{$name};
}

my $print_api_result = sub {
    my ($data, $schema, $options) = @_;
    PVE::CLIFormatter::print_api_result($data, $schema, undef, $options);
};

my $print_perm_result = sub {
    my ($data, $schema, $options) = @_;

    if (!defined($options->{'output-format'}) || $options->{'output-format'} eq 'text') {
	my $table_schema = {
	    type => 'array',
	    items => {
		type => 'object',
		properties => {
		    'path' => { type => 'string', title => 'ACL path' },
		    'permissions' => { type => 'string', title => 'Permissions' },
		},
	    },
	};
	my $table_data = [];
	foreach my $path (sort keys %$data) {
	    my $value = '';
	    my $curr = $data->{$path};
	    foreach my $perm (sort keys %$curr) {
		$value .= "\n" if $value;
		$value .= $perm;
		$value .= " (*)" if $curr->{$perm};
	    }
	    push @$table_data, { path => $path, permissions => $value };
	}
	PVE::CLIFormatter::print_api_result($table_data, $table_schema, undef, $options);
	print "Permissions marked with '(*)' have the 'propagate' flag set.\n";
    } else {
	PVE::CLIFormatter::print_api_result($data, $schema, undef, $options);
    }
};

__PACKAGE__->register_method({
    name => 'token_permissions',
    path => 'token_permissions',
    method => 'GET',
    description => 'Retrieve effective permissions of given token.',
    parameters => {
	additionalProperties => 0,
	properties => {
	    userid => get_standard_option('userid'),
	    tokenid => get_standard_option('token-subid'),
	    path => get_standard_option('acl-path', {
		description => "Only dump this specific path, not the whole tree.",
		optional => 1,
	    }),
	},
    },
    returns => {
	type => 'object',
	description => 'Hash of structure "path" => "privilege" => "propagate boolean".',
    },
    code => sub {
	my ($param) = @_;

	my $token_subid = extract_param($param, "tokenid");
	$param->{userid} = PVE::AccessControl::join_tokenid($param->{userid}, $token_subid);

	return PVE::API2::AccessControl->permissions($param);
    }});

our $cmddef = {
    user => {
	add    => [ 'PVE::API2::User', 'create_user', ['userid'] ],
	modify => [ 'PVE::API2::User', 'update_user', ['userid'] ],
	delete => [ 'PVE::API2::User', 'delete_user', ['userid'] ],
	list   => [ 'PVE::API2::User', 'index', [], {}, $print_api_result, $PVE::RESTHandler::standard_output_options],
	permissions => [ 'PVE::API2::AccessControl', 'permissions', ['userid'], {}, $print_perm_result, $PVE::RESTHandler::standard_output_options],
	tfa => {
	    delete => [ 'PVE::API2::AccessControl', 'change_tfa', ['userid'], { action => 'delete', key => undef, config => undef, response => undef, }, ],
	},
	token => {
	    add    => [ 'PVE::API2::User', 'generate_token', ['userid', 'tokenid'], {}, $print_api_result, $PVE::RESTHandler::standard_output_options ],
	    modify    => [ 'PVE::API2::User', 'update_token_info', ['userid', 'tokenid'], {}, $print_api_result, $PVE::RESTHandler::standard_output_options ],
	    remove    => [ 'PVE::API2::User', 'remove_token', ['userid', 'tokenid'], {}, $print_api_result, $PVE::RESTHandler::standard_output_options ],
	    list   => [ 'PVE::API2::User', 'token_index', ['userid'], {}, $print_api_result, $PVE::RESTHandler::standard_output_options],
	    permissions => [ __PACKAGE__, 'token_permissions', ['userid', 'tokenid'], {}, $print_perm_result, $PVE::RESTHandler::standard_output_options],
	}
    },
    group => {
	add    => [ 'PVE::API2::Group', 'create_group', ['groupid'] ],
	modify => [ 'PVE::API2::Group', 'update_group', ['groupid'] ],
	delete => [ 'PVE::API2::Group', 'delete_group', ['groupid'] ],
	list   => [ 'PVE::API2::Group', 'index', [], {}, $print_api_result, $PVE::RESTHandler::standard_output_options],
    },
    role => {
	add    => [ 'PVE::API2::Role', 'create_role', ['roleid'] ],
	modify => [ 'PVE::API2::Role', 'update_role', ['roleid'] ],
	delete => [ 'PVE::API2::Role', 'delete_role', ['roleid'] ],
	list   => [ 'PVE::API2::Role', 'index', [], {}, $print_api_result, $PVE::RESTHandler::standard_output_options],
    },
    acl => {
	modify => [ 'PVE::API2::ACL', 'update_acl', ['path'], { delete => 0 }],
	delete => [ 'PVE::API2::ACL', 'update_acl', ['path'], { delete => 1 }],
	list   => [ 'PVE::API2::ACL', 'read_acl', [], {}, $print_api_result, $PVE::RESTHandler::standard_output_options],
    },
    realm => {
	add    => [ 'PVE::API2::Domains', 'create', ['realm'] ],
	modify => [ 'PVE::API2::Domains', 'update', ['realm'] ],
	delete => [ 'PVE::API2::Domains', 'delete', ['realm'] ],
	list   => [ 'PVE::API2::Domains', 'index', [], {}, $print_api_result, $PVE::RESTHandler::standard_output_options],
	sync   => [ 'PVE::API2::Domains', 'sync', ['realm'], ],
    },

    ticket => [ 'PVE::API2::AccessControl', 'create_ticket', ['username'], undef,
		sub {
		    my ($res) = @_;
		    print "$res->{ticket}\n";
		}],

    passwd => [ 'PVE::API2::AccessControl', 'change_password', ['userid'] ],

    useradd => { alias => 'user add' },
    usermod => { alias => 'user modify' },
    userdel => { alias => 'user delete' },

    groupadd => { alias => 'group add' },
    groupmod => { alias => 'group modify' },
    groupdel => { alias => 'group delete' },

    roleadd => { alias => 'role add' },
    rolemod => { alias => 'role modify' },
    roledel => { alias => 'role delete' },

    aclmod => { alias => 'acl modify' },
    acldel => { alias => 'acl delete' },
};

# FIXME: HACK! The pool API is in pve-manager as it needs access to storage guest and RRD stats,
# so we only add the pool commands if the API module is available (required for boots-trapping)
my $have_pool_api;
eval {
    require PVE::API2::Pool;
    PVE::API2::Pool->import();
    $have_pool_api = 1;
};

if ($have_pool_api) {
    $cmddef->{pool} = {
	add => [ 'PVE::API2::Pool', 'create_pool', ['poolid'] ],
	modify => [ 'PVE::API2::Pool', 'update_pool', ['poolid'] ],
	delete => [ 'PVE::API2::Pool', 'delete_pool', ['poolid'] ],
	list   => [ 'PVE::API2::Pool', 'index', [], {}, $print_api_result, $PVE::RESTHandler::standard_output_options],
    };
}

1;

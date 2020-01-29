package PVE::CLI::pveum;

use strict;
use warnings;

use PVE::RPCEnvironment;
use PVE::API2::User;
use PVE::API2::Group;
use PVE::API2::Role;
use PVE::API2::ACL;
use PVE::API2::AccessControl;
use PVE::CLIFormatter;
use PVE::CLIHandler;
use PVE::PTY;
use PVE::RESTHandler;

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

our $cmddef = {
    user => {
	add    => [ 'PVE::API2::User', 'create_user', ['userid'] ],
	modify => [ 'PVE::API2::User', 'update_user', ['userid'] ],
	delete => [ 'PVE::API2::User', 'delete_user', ['userid'] ],
	list   => [ 'PVE::API2::User', 'index', [], {}, $print_api_result, $PVE::RESTHandler::standard_output_options],
	token => {
	    add    => [ 'PVE::API2::User', 'generate_token', ['userid', 'tokenid'], {}, $print_api_result, $PVE::RESTHandler::standard_output_options ],
	    modify    => [ 'PVE::API2::User', 'update_token_info', ['userid', 'tokenid'], {}, $print_api_result, $PVE::RESTHandler::standard_output_options ],
	    remove    => [ 'PVE::API2::User', 'remove_token', ['userid', 'tokenid'], {}, $print_api_result, $PVE::RESTHandler::standard_output_options ],
	    list   => [ 'PVE::API2::User', 'token_index', ['userid'], {}, $print_api_result, $PVE::RESTHandler::standard_output_options],
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

1;

package PVE::CLI::pveum;

use strict;
use warnings;
use Getopt::Long;
use PVE::Tools qw(run_command);
use PVE::Cluster;
use PVE::SafeSyslog;
use PVE::AccessControl;
use File::Path qw(make_path remove_tree);
use Term::ReadLine;
use PVE::INotify;
use PVE::RPCEnvironment;
use PVE::API2::User;
use PVE::API2::Group;
use PVE::API2::Role;
use PVE::API2::ACL;
use PVE::API2::AccessControl;
use PVE::JSONSchema qw(get_standard_option);
use PVE::CLIHandler;

use base qw(PVE::CLIHandler);

sub setup_environment {
    PVE::RPCEnvironment->setup_default_cli_env();
}

sub read_password {
    # return $ENV{PVE_PW_TICKET} if defined($ENV{PVE_PW_TICKET});

    my $term = new Term::ReadLine ('pveum');
    my $attribs = $term->Attribs;
    $attribs->{redisplay_function} = $attribs->{shadow_redisplay};
    my $input = $term->readline('Enter new password: ');
    my $conf = $term->readline('Retype new password: ');
    die "Passwords do not match.\n" if ($input ne $conf);
    return $input;
}

our $cmddef = {
    user => {
	add    => [ 'PVE::API2::User', 'create_user', ['userid'] ],
	modify => [ 'PVE::API2::User', 'update_user', ['userid'] ],
	delete => [ 'PVE::API2::User', 'delete_user', ['userid'] ],
    },
    group => {
	add    => [ 'PVE::API2::Group', 'create_group', ['groupid'] ],
	modify => [ 'PVE::API2::Group', 'update_group', ['groupid'] ],
	delete => [ 'PVE::API2::Group', 'delete_group', ['groupid'] ],
    },
    role => {
	add    => [ 'PVE::API2::Role', 'create_role', ['roleid'] ],
	modify => [ 'PVE::API2::Role', 'update_role', ['roleid'] ],
	delete => [ 'PVE::API2::Role', 'delete_role', ['roleid'] ],
    },
    acl => {
	modify => [ 'PVE::API2::ACL', 'update_acl', ['path'], { delete => 0 }],
	delete => [ 'PVE::API2::ACL', 'update_acl', ['path'], { delete => 1 }],
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

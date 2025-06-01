#!/usr/bin/env perl

use strict;
use warnings;

use lib qw(..);

use PVE::Tools;

use Test::More;
use Test::MockModule;

use PVE::AccessControl;
use PVE::RPCEnvironment;
use PVE::API2::AccessControl;

my $cluster_module = Test::MockModule->new('PVE::Cluster');
# make cfs_update a stub as it's not relevant to the test cases and will
# make these tests fail if the user doesn't have access to the cluster ipcc
$cluster_module->noop('cfs_update');

my $rpcenv = PVE::RPCEnvironment->init('cli');
$rpcenv->init_request(userconfig => 'api-get-permissions-test.cfg');

my ($handler, $handler_info) = PVE::API2::AccessControl->find_handler('GET', 'permissions');

# stranger = user without Sys.Audit permission
my $stranger_perms = $rpcenv->get_effective_permissions('stranger@pve');
my $stranger_privsep_perms = $rpcenv->get_effective_permissions('stranger@pve!privsep');

my $stranger_user_tests = [
    {
        description => 'get stranger\'s perms without passing the user\'s userid',
        rpcuser => 'stranger@pve',
        params => {},
        result => $stranger_perms,
    },
    {
        description => 'get stranger\'s perms with passing the user\'s userid',
        rpcuser => 'stranger@pve',
        params => {
            userid => 'stranger@pve',
        },
        result => $stranger_perms,
    },
    {
        description => 'get stranger-owned non-priv-sep\'d token\'s perms from stranger user',
        rpcuser => 'stranger@pve',
        params => {
            userid => 'stranger@pve!noprivsep',
        },
        result => $stranger_perms,
    },
    {
        description => 'get stranger-owned priv-sep\'d token\'s perms from stranger user',
        rpcuser => 'stranger@pve',
        params => {
            userid => 'stranger@pve!privsep',
        },
        result => $stranger_privsep_perms,
    },
    {
        description => 'get auditor\'s perms from stranger user',
        should_fail => 1,
        rpcuser => 'stranger@pve',
        params => {
            userid => 'auditor@pam',
        },
    },
    {
        description => 'get auditor-owned token\'s perms from stranger user',
        should_fail => 1,
        rpcuser => 'stranger@pve',
        params => {
            userid => 'auditor@pam!noprivsep',
        },
    },
];

my $stranger_nonprivsep_tests = [
    {
        description =>
            'get stranger-owned non-priv-sep\'d token\'s perms without passing the token',
        rpcuser => 'stranger@pve!noprivsep',
        params => {},
        result => $stranger_perms,
    },
    {
        description =>
            'get stranger-owned non-priv-sep\'d token\'s perms with passing the token',
        rpcuser => 'stranger@pve!noprivsep',
        params => {
            userid => 'stranger@pve!noprivsep',
        },
        result => $stranger_perms,
    },
    {
        description => 'get stranger\'s perms from stranger-owned non-priv-sep\'d token',
        should_fail => 1,
        rpcuser => 'stranger@pve!noprivsep',
        params => {
            userid => 'stranger@pve',
        },
    },
    {
        description => 'get stranger-owned priv-sep\'d token\'s perms '
            . 'from stranger-owned non-priv-sep\'d token',
        should_fail => 1,
        rpcuser => 'stranger@pve!noprivsep',
        params => {
            userid => 'stranger@pve!privsep',
        },
    },
    {
        description =>
            'get auditor-owned token\'s perms from stranger-owned non-priv-sep\'d token',
        should_fail => 1,
        rpcuser => 'stranger@pve!noprivsep',
        params => {
            userid => 'auditor@pam!noprivsep',
        },
    },
];

my $stranger_privsep_tests = [
    {
        description =>
            'get stranger-owned priv-sep\'d token\'s perms without passing the token',
        rpcuser => 'stranger@pve!privsep',
        params => {},
        result => $stranger_privsep_perms,
    },
    {
        description => 'get stranger-owned priv-sep\'d token\'s perms with passing the token',
        rpcuser => 'stranger@pve!privsep',
        params => {
            userid => 'stranger@pve!privsep',
        },
        result => $stranger_privsep_perms,
    },
    {
        description => 'get stranger\'s perms from stranger-owned priv-sep\'d token',
        should_fail => 1,
        rpcuser => 'stranger@pve!privsep',
        params => {
            userid => 'stranger@pve',
        },
    },
    {
        description => 'get stranger-owned non-priv-sep\'d token\'s perms '
            . 'from stranger-owned priv-sep\'d token',
        should_fail => 1,
        rpcuser => 'stranger@pve!privsep',
        params => {
            userid => 'stranger@pve!noprivsep',
        },
    },
    {
        description => 'get auditor-owned token\'s perms from stranger-owned priv-sep\'d token',
        should_fail => 1,
        rpcuser => 'stranger@pve!privsep',
        params => {
            userid => 'auditor@pam!noprivsep',
        },
    },
];

# auditor = user with Sys.Audit permission
my $auditor_perms = $rpcenv->get_effective_permissions('auditor@pam');
my $auditor_privsep_perms = $rpcenv->get_effective_permissions('auditor@pam!privsep');

my $auditor_user_tests = [
    {
        description => 'get auditor\'s perms without passing the user\'s userid',
        rpcuser => 'auditor@pam',
        params => {},
        result => $auditor_perms,
    },
    {
        description => 'get auditor\'s perms with passing the user\'s userid',
        rpcuser => 'auditor@pam',
        params => {
            userid => 'auditor@pam',
        },
        result => $auditor_perms,
    },
    {
        description => 'get auditor-owned non-priv-sep\'d token\'s perms from auditor user',
        rpcuser => 'auditor@pam',
        params => {
            userid => 'auditor@pam!noprivsep',
        },
        result => $auditor_perms,
    },
    {
        description => 'get auditor-owned priv-sep\'d token\'s perms from auditor user',
        rpcuser => 'auditor@pam',
        params => {
            userid => 'auditor@pam!privsep',
        },
        result => $auditor_privsep_perms,
    },
    {
        description => 'get stranger\'s perms from auditor user',
        rpcuser => 'auditor@pam',
        params => {
            userid => 'stranger@pve',
        },
        result => $stranger_perms,
    },
    {
        description => 'get stranger-owned token\'s perms from auditor user',
        rpcuser => 'auditor@pam',
        params => {
            userid => 'stranger@pve!noprivsep',
        },
        result => $stranger_perms,
    },
];

my $auditor_nonprivsep_tests = [
    {
        description =>
            'get auditor-owned non-priv-sep\'d token\'s perms without passing the token',
        rpcuser => 'auditor@pam!noprivsep',
        params => {},
        result => $auditor_perms,
    },
    {
        description =>
            'get auditor-owned non-priv-sep\'d token\'s perms with passing the token',
        rpcuser => 'auditor@pam!noprivsep',
        params => {
            userid => 'auditor@pam!noprivsep',
        },
        result => $auditor_perms,
    },
    {
        description => 'get auditor\'s perms from auditor-owned non-priv-sep\'d token',
        rpcuser => 'auditor@pam!noprivsep',
        params => {
            userid => 'auditor@pam',
        },
        result => $auditor_perms,
    },
    {
        description => 'get auditor-owned priv-sep\'d token\'s perms '
            . 'from auditor-owned non-priv-sep\'d token',
        rpcuser => 'auditor@pam!noprivsep',
        params => {
            userid => 'auditor@pam!privsep',
        },
        result => $auditor_privsep_perms,
    },
    {
        description =>
            'get stranger-owned token\'s perms from auditor-owned non-priv-sep\'d token',
        rpcuser => 'auditor@pam!noprivsep',
        params => {
            userid => 'stranger@pve!noprivsep',
        },
        result => $stranger_perms,
    },
];

my $auditor_privsep_tests = [
    {
        description => 'get auditor-owned priv-sep\'d token\'s perms without passing the token',
        rpcuser => 'auditor@pam!privsep',
        params => {},
        result => $auditor_privsep_perms,
    },
    {
        description => 'get auditor-owned priv-sep\'d token\'s perms with passing the token',
        rpcuser => 'auditor@pam!privsep',
        params => {
            userid => 'auditor@pam!privsep',
        },
        result => $auditor_privsep_perms,
    },
    {
        description => 'get auditor\'s perms from auditor-owned priv-sep\'d token',
        should_fail => 1,
        rpcuser => 'auditor@pam!privsep',
        params => {
            userid => 'auditor@pam',
        },
    },
    {
        description => 'get auditor-owned non-priv-sep\'d token\'s perms '
            . 'from auditor-owned priv-sep\'d token',
        should_fail => 1,
        rpcuser => 'auditor@pam!privsep',
        params => {
            userid => 'auditor@pam!noprivsep',
        },
    },
    {
        description => 'get stranger-owned token\'s perms from auditor-owned priv-sep\'d token',
        should_fail => 1,
        rpcuser => 'auditor@pam!privsep',
        params => {
            userid => 'stranger@pve!noprivsep',
        },
    },
];

my $tests = [
    @$stranger_user_tests,
    @$stranger_nonprivsep_tests,
    @$stranger_privsep_tests,
    @$auditor_user_tests,
    @$auditor_nonprivsep_tests,
    @$auditor_privsep_tests,
];

plan(tests => scalar($tests->@*));

for my $case ($tests->@*) {
    $rpcenv->set_user($case->{rpcuser});

    my $result = eval { $handler->handle($handler_info, $case->{params}) };

    if ($@) {
        my $should_fail = exists($case->{should_fail}) ? $case->{should_fail} : 0;
        is(defined($@), $should_fail, "should fail: $case->{description}") || diag explain $@;
    } else {
        is_deeply($result, $case->{result}, $case->{description});
    }
}

done_testing();

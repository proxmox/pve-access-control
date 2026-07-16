#!/usr/bin/perl

use v5.36;

use lib qw(..);

use Test::MockModule;
use Test::More;

use PVE::AccessControl;
use PVE::API2::User;
use PVE::RPCEnvironment;

# Check the privileges needed to manage API tokens of other users, running the API permission check
# and handler like a request does, with the cluster file system and token secrets mocked out.

my $user_cfg_raw;

my $access_control_module = Test::MockModule->new('PVE::AccessControl');
$access_control_module->mock(
    lock_user_config => sub { $_[0]->() },
    # token create and update look up the datacenter token policy, run them without one
    cfs_read_file => sub($file) {
        die "unexpected cfs_read_file('$file') call\n" if $file ne 'datacenter.cfg';
        return {};
    },
);

my $api_user_module = Test::MockModule->new('PVE::API2::User');
$api_user_module->mock(
    cfs_read_file => sub($file) {
        die "unexpected cfs_read_file('$file') call\n" if $file ne 'user.cfg';
        return PVE::AccessControl::parse_user_config($file, $user_cfg_raw);
    },
    cfs_write_file => sub($file, $cfg) {
        die "unexpected cfs_write_file('$file') call\n" if $file ne 'user.cfg';
        $user_cfg_raw = PVE::AccessControl::write_user_config($file, $cfg);
    },
);

my $token_config_module = Test::MockModule->new('PVE::TokenConfig');
$token_config_module->mock(
    generate_token => sub($tokenid) { return 'secret' },
    delete_token => sub($tokenid) { return },
);

my $rpcenv = PVE::RPCEnvironment->init('cli');

# 'access-admin' can modify ACLs below '/access' only, 'user-admin' cannot modify ACLs at all.
sub call($authuser, $method, $param) {
    $user_cfg_raw = <<~'EOF';
        user:root@pam:1:0::::::
        user:admin@pve:1:0::::::
        user:access-admin@pve:1:0::::::
        user:user-admin@pve:1:0::::::
        user:alice@pve:1:0::::::
        token:alice@pve!full:0:0::
        token:alice@pve!sep:0:1::

        acl:1:/:admin@pve,alice@pve:Administrator:
        acl:1:/access:access-admin@pve:Administrator:
        acl:1:/access:alice@pve!sep,user-admin@pve:PVEUserAdmin:
        EOF
    $rpcenv->{user_cfg} = PVE::AccessControl::parse_user_config('user.cfg', $user_cfg_raw);
    $rpcenv->{aclcache} = {};
    $rpcenv->set_user($authuser);

    my $info = PVE::API2::User->map_method_by_name($method);
    eval {
        $rpcenv->check_api2_permissions($info->{permissions}, $authuser, {%$param});
        PVE::API2::User->$method({%$param});
    };
    return $@;
}

my $denied = qr!Permission check failed \(/, Permissions\.Modify\)!;

sub generate($authuser, $userid, $privsep) {
    return call(
        $authuser,
        'generate_token',
        { userid => $userid, tokenid => 'new', privsep => $privsep },
    );
}

sub update($authuser, $tokenid, %param) {
    return call($authuser, 'update_token_info',
        { userid => 'alice@pve', tokenid => $tokenid, %param });
}

is(generate('alice@pve', 'alice@pve', 0), '', 'owner can create a token without privsep');
is(generate('user-admin@pve', 'alice@pve', 1), '', 'user admin can create a privsep token');
like(
    generate('user-admin@pve', 'alice@pve', 0),
    $denied,
    'user admin cannot create a token without privsep',
);
like(
    generate('access-admin@pve', 'root@pam', 0),
    $denied,
    "'Permissions.Modify' on '/access' does not allow creating a token without privsep",
);
like(
    generate('alice@pve!sep', 'alice@pve', 0),
    $denied,
    'privsep token cannot create a token without privsep for its owner',
);
is(generate('admin@pve', 'alice@pve', 0), '', "admin on '/' can create a token without privsep");

is(update('alice@pve', 'full', regenerate => 1), '',
    'owner can regenerate a token without privsep');
is(update('admin@pve', 'sep', regenerate => 1), '', "admin on '/' can regenerate a privsep token");
like(
    update('user-admin@pve', 'sep', regenerate => 1),
    $denied,
    'user admin cannot regenerate a privsep token',
);
like(update('user-admin@pve', 'sep', privsep => 0), $denied, 'user admin cannot disable privsep');
like(
    update('user-admin@pve', 'full', comment => 'x'),
    $denied,
    'user admin cannot update a token without privsep',
);
is(update('user-admin@pve', 'full', privsep => 1), '', 'user admin can enable privsep');
is(update('user-admin@pve', 'sep', comment => 'x'), '', 'user admin can update a privsep token');

is(
    call('user-admin@pve', 'remove_token', { userid => 'alice@pve', tokenid => 'full' }),
    '',
    'user admin can remove a token without privsep',
);

done_testing();

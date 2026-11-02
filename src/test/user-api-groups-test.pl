#!/usr/bin/perl

use v5.36;

use lib qw(..);

use Test::MockModule;
use Test::More;

use PVE::AccessControl;
use PVE::API2::User;

# Exercise the group handling of the user create and update API handlers with the real schema
# validation and user config parser/writer, mocking out the cluster file system.

my $user_cfg_raw;

my $read = sub($file) {
    return PVE::AccessControl::parse_user_config($file, $user_cfg_raw) if $file eq 'user.cfg';
    return { ids => { pve => { type => 'pve' } } } if $file eq 'domains.cfg';
    die "unexpected cfs_read_file('$file') call\n";
};

my $access_control_module = Test::MockModule->new('PVE::AccessControl');
$access_control_module->mock(cfs_read_file => $read);
$access_control_module->mock(lock_user_config => sub { $_[0]->() });

my $api_user_module = Test::MockModule->new('PVE::API2::User');
$api_user_module->mock(cfs_read_file => $read);
$api_user_module->mock(
    cfs_write_file => sub($file, $cfg) {
        die "unexpected cfs_write_file('$file') call\n" if $file ne 'user.cfg';
        $user_cfg_raw = PVE::AccessControl::write_user_config($file, $cfg);
    },
);

sub groups_of($userid) {
    my $cfg = PVE::AccessControl::parse_user_config('user.cfg', $user_cfg_raw);
    return join(',', sort keys $cfg->{users}->{$userid}->{groups}->%*);
}

sub reset_config() {
    $user_cfg_raw = "user:existing\@pve:1:0::::::\n\ngroup:0:::\ngroup:other:existing\@pve::\n";
}

reset_config();
PVE::API2::User->create_user({ userid => 'new@pve', groups => '0' });
is(groups_of('new@pve'), '0', "create adds user to group '0'");

reset_config();
PVE::API2::User->update_user({ userid => 'existing@pve', groups => '0' });
is(groups_of('existing@pve'), '0', "update sets group '0'");

reset_config();
PVE::API2::User->update_user({ userid => 'existing@pve', groups => '0', append => 1 });
is(groups_of('existing@pve'), '0,other', "update appends group '0'");

reset_config();
PVE::API2::User->update_user({ userid => 'existing@pve', groups => '' });
is(groups_of('existing@pve'), '', 'update with empty groups clears groups');

done_testing();

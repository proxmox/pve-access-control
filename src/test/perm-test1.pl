#!/usr/bin/perl -w

use strict;
use warnings;

use Getopt::Long;

use PVE::Tools;

use PVE::AccessControl;
use PVE::RPCEnvironment;

my $rpcenv = PVE::RPCEnvironment->init('cli');

my $cfgfn = "test1.cfg";
$rpcenv->init_request(userconfig => $cfgfn);

sub check_roles {
    my ($user, $path, $expected_result) = @_;

    my $roles = PVE::AccessControl::roles($rpcenv->{user_cfg}, $user, $path);
    my $res = join(',', sort keys %$roles);

    die "unexpected result\nneed '${expected_result}'\ngot '$res'\n"
        if $res ne $expected_result;

    print "ROLES:$path:$user:$res\n";
}

sub check_permission {
    my ($user, $path, $expected_result) = @_;

    my $perm = $rpcenv->permissions($user, $path);
    my $res = join(',', sort keys %$perm);

    die "unexpected result\nneed '${expected_result}'\ngot '$res'\n"
        if $res ne $expected_result;

    $perm = $rpcenv->permissions($user, $path);
    $res = join(',', sort keys %$perm);
    die "unexpected result (compiled)\nneed '${expected_result}'\ngot '$res'\n"
        if $res ne $expected_result;

    print "PERM:$path:$user:$res\n";
}

check_roles('max@pve', '/', '');
check_roles('max@pve', '/vms', 'vm_admin');

#user permissions overrides group permissions
check_roles('max@pve', '/vms/100', 'customer');
check_roles('max@pve', '/vms/101', 'vm_admin');

check_permission('max@pve', '/', '');
check_permission('max@pve', '/vms', 'Permissions.Modify,VM.Allocate,VM.Audit,VM.Console');
check_permission('max@pve', '/vms/100', 'VM.Audit,VM.PowerMgmt');

check_permission('alex@pve', '/vms', '');
check_permission('alex@pve', '/vms/100', 'VM.Audit,VM.PowerMgmt');

# PVEVMAdmin -> no Permissions.Modify!
check_permission(
    'alex@pve',
    '/vms/300',
    '' # sorted, comma-separated expected privilege string
        . 'VM.Allocate,VM.Audit,VM.Backup,VM.Clone,VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,'
        . 'VM.Config.Disk,VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,'
        . 'VM.Console,VM.GuestAgent.Audit,VM.GuestAgent.FileRead,VM.GuestAgent.FileSystemMgmt,'
        . 'VM.GuestAgent.FileWrite,VM.GuestAgent.Unrestricted,VM.Migrate,VM.PowerMgmt,VM.Replicate,'
        . 'VM.Snapshot,VM.Snapshot.Rollback',
);
# Administrator -> Permissions.Modify!
check_permission(
    'alex@pve',
    '/vms/400',
    '' # sorted, comma-separated expected privilege string, loosely grouped by prefix
        . 'Datastore.Allocate,Datastore.AllocateSpace,Datastore.AllocateTemplate,Datastore.Audit,'
        . 'Group.Allocate,'
        . 'Mapping.Audit,Mapping.Modify,Mapping.Use,'
        . 'Permissions.Modify,'
        . 'Pool.Allocate,Pool.Audit,'
        . 'Realm.Allocate,Realm.AllocateUser,'
        . 'SDN.Allocate,SDN.Audit,SDN.Use,'
        . 'Sys.AccessNetwork,Sys.Audit,Sys.Console,Sys.Incoming,Sys.Modify,Sys.PowerMgmt,Sys.Syslog,'
        . 'User.Modify,'
        . 'VM.Allocate,VM.Audit,VM.Backup,VM.Clone,VM.Config.CDROM,VM.Config.CPU,VM.Config.Cloudinit,'
        . 'VM.Config.Disk,VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,'
        . 'VM.Console,VM.GuestAgent.Audit,VM.GuestAgent.FileRead,VM.GuestAgent.FileSystemMgmt,'
        . 'VM.GuestAgent.FileWrite,VM.GuestAgent.Unrestricted,VM.Migrate,VM.PowerMgmt,VM.Replicate,'
        . 'VM.Snapshot,VM.Snapshot.Rollback',
);

check_roles('max@pve', '/vms/200', 'storage_manager');
check_roles('joe@pve', '/vms/200', 'vm_admin');
check_roles('sue@pve', '/vms/200', 'NoAccess');

print "all tests passed\n";

exit(0);

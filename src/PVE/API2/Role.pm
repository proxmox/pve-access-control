package PVE::API2::Role;

use strict;
use warnings;

use PVE::AccessControl ();
use PVE::Cluster qw(cfs_read_file cfs_write_file);
use PVE::Exception qw(raise_param_exc);
use PVE::JSONSchema qw(get_standard_option register_standard_option);

use base qw(PVE::RESTHandler);

register_standard_option(
    'role-id',
    {
        type => 'string',
        format => 'pve-roleid',
    },
);
register_standard_option(
    'role-privs',
    {
        type => 'string',
        format => 'pve-priv-list',
        optional => 1,
    },
);

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => "Role index.",
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
                roleid => get_standard_option('role-id'),
                privs => get_standard_option('role-privs'),
                special => { type => 'boolean', optional => 1, default => 0 },
            },
        },
        links => [{ rel => 'child', href => "{roleid}" }],
    },
    code => sub {
        my ($param) = @_;

        my $res = [];

        my $usercfg = cfs_read_file("user.cfg");

        foreach my $role (keys %{ $usercfg->{roles} }) {
            my $privs = join(',', sort keys %{ $usercfg->{roles}->{$role} });
            push @$res,
                {
                    roleid => $role,
                    privs => $privs,
                    special => PVE::AccessControl::role_is_special($role),
                };
        }

        return $res;
    },
});

__PACKAGE__->register_method({
    name => 'create_role',
    protected => 1,
    path => '',
    method => 'POST',
    permissions => {
        check => ['perm', '/access', ['Sys.Modify']],
    },
    description => "Create new role.",
    parameters => {
        additionalProperties => 0,
        properties => {
            roleid => get_standard_option('role-id'),
            privs => get_standard_option('role-privs'),
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $role = $param->{roleid};

        if ($role =~ /^PVE/i) {
            raise_param_exc({
                roleid =>
                    "cannot use role ID starting with the (case-insensitive) 'PVE' namespace",
            });
        }

        PVE::AccessControl::lock_user_config(
            sub {
                my $usercfg = cfs_read_file("user.cfg");

                die "role '$role' already exists\n" if $usercfg->{roles}->{$role};

                $usercfg->{roles}->{$role} = {};

                PVE::AccessControl::add_role_privs($role, $usercfg, $param->{privs});

                cfs_write_file("user.cfg", $usercfg);
            },
            "create role failed",
        );

        return undef;
    },
});

__PACKAGE__->register_method({
    name => 'update_role',
    protected => 1,
    path => '{roleid}',
    method => 'PUT',
    permissions => {
        check => ['perm', '/access', ['Sys.Modify']],
    },
    description => "Update an existing role.",
    parameters => {
        additionalProperties => 0,
        properties => {
            roleid => get_standard_option('role-id'),
            privs => get_standard_option('role-privs'),
            append => { type => 'boolean', optional => 1, requires => 'privs' },
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $role = $param->{roleid};

        die "auto-generated role '$role' cannot be modified\n"
            if PVE::AccessControl::role_is_special($role);

        PVE::AccessControl::lock_user_config(
            sub {
                my $usercfg = cfs_read_file("user.cfg");

                die "role '$role' does not exist\n" if !$usercfg->{roles}->{$role};

                $usercfg->{roles}->{$role} = {} if !$param->{append};

                PVE::AccessControl::add_role_privs($role, $usercfg, $param->{privs});

                cfs_write_file("user.cfg", $usercfg);
            },
            "update role failed",
        );

        return undef;
    },
});

__PACKAGE__->register_method({
    name => 'read_role',
    path => '{roleid}',
    method => 'GET',
    permissions => {
        user => 'all',
    },
    description => "Get role configuration.",
    parameters => {
        additionalProperties => 0,
        properties => {
            roleid => get_standard_option('role-id'),
        },
    },
    returns => {
        type => "object",
        additionalProperties => 0,
        properties => PVE::AccessControl::create_priv_properties(),
    },
    code => sub {
        my ($param) = @_;

        my $usercfg = cfs_read_file("user.cfg");

        my $role = $param->{roleid};

        my $data = $usercfg->{roles}->{$role};

        die "role '$role' does not exist\n" if !$data;

        return $data;
    },
});

__PACKAGE__->register_method({
    name => 'delete_role',
    protected => 1,
    path => '{roleid}',
    method => 'DELETE',
    permissions => {
        check => ['perm', '/access', ['Sys.Modify']],
    },
    description => "Delete role.",
    parameters => {
        additionalProperties => 0,
        properties => {
            roleid => get_standard_option('role-id'),
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $role = $param->{roleid};

        die "auto-generated role '$role' cannot be deleted\n"
            if PVE::AccessControl::role_is_special($role);

        PVE::AccessControl::lock_user_config(
            sub {
                my $usercfg = cfs_read_file("user.cfg");

                die "role '$role' does not exist\n" if !$usercfg->{roles}->{$role};

                delete($usercfg->{roles}->{$role});

                # fixme: delete role from acl?

                cfs_write_file("user.cfg", $usercfg);
            },
            "delete role failed",
        );

        return undef;
    },
});

1;

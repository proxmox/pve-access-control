package PVE::API2::ACL;

use strict;
use warnings;
use PVE::Cluster qw (cfs_read_file cfs_write_file);
use PVE::Tools qw(split_list);
use PVE::AccessControl;
use PVE::Exception qw(raise_param_exc);
use PVE::JSONSchema qw(get_standard_option register_standard_option);

use PVE::SafeSyslog;

use PVE::RESTHandler;

use base qw(PVE::RESTHandler);

register_standard_option(
    'acl-propagate',
    {
        description => "Allow to propagate (inherit) permissions.",
        type => 'boolean',
        optional => 1,
        default => 1,
    },
);
register_standard_option(
    'acl-path',
    {
        description => "Access control path",
        type => 'string',
    },
);

__PACKAGE__->register_method({
    name => 'read_acl',
    path => '',
    method => 'GET',
    description => "Get Access Control List (ACLs).",
    permissions => {
        description =>
            "The returned list is restricted to objects where you have rights to modify permissions.",
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
            additionalProperties => 0,
            properties => {
                propagate => get_standard_option('acl-propagate'),
                path => get_standard_option('acl-path'),
                type => { type => 'string', enum => ['user', 'group', 'token'] },
                ugid => { type => 'string' },
                roleid => { type => 'string' },
            },
        },
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();
        my $res = [];

        my $usercfg = $rpcenv->{user_cfg};
        if (!$usercfg || !$usercfg->{acl_root}) {
            return $res;
        }

        my $audit = $rpcenv->check($authuser, '/access', ['Sys.Audit'], 1);

        my $root = $usercfg->{acl_root};
        PVE::AccessControl::iterate_acl_tree(
            "/",
            $root,
            sub {
                my ($path, $node) = @_;
                foreach my $type (qw(user group token)) {
                    my $d = $node->{"${type}s"};
                    next if !$d;
                    next if !($audit || $rpcenv->check_perm_modify($authuser, $path, 1));
                    foreach my $id (keys %$d) {
                        foreach my $role (keys %{ $d->{$id} }) {
                            my $propagate = $d->{$id}->{$role};
                            push @$res,
                                {
                                    path => $path,
                                    type => $type,
                                    ugid => $id,
                                    roleid => $role,
                                    propagate => $propagate,
                                };
                        }
                    }
                }
            },
        );

        return $res;
    },
});

__PACKAGE__->register_method({
    name => 'update_acl',
    protected => 1,
    path => '',
    method => 'PUT',
    permissions => {
        check => ['perm-modify', '{path}'],
    },
    description => "Update Access Control List (add or remove permissions).",
    parameters => {
        additionalProperties => 0,
        properties => {
            propagate => get_standard_option('acl-propagate'),
            path => get_standard_option('acl-path'),
            users => {
                description => "List of users.",
                type => 'string',
                format => 'pve-userid-list',
                optional => 1,
            },
            groups => {
                description => "List of groups.",
                type => 'string',
                format => 'pve-groupid-list',
                optional => 1,
            },
            tokens => {
                description => "List of API tokens.",
                type => 'string',
                format => 'pve-tokenid-list',
                optional => 1,
            },
            roles => {
                description => "List of roles.",
                type => 'string',
                format => 'pve-roleid-list',
            },
            delete => {
                description => "Remove permissions (instead of adding it).",
                type => 'boolean',
                optional => 1,
            },
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        if (!($param->{users} || $param->{groups} || $param->{tokens})) {
            raise_param_exc({
                map { $_ => "either 'users', 'groups' or 'tokens' is required." }
                    qw(users groups tokens)
            });
        }

        my $path = PVE::AccessControl::normalize_path($param->{path});
        raise_param_exc({ path => "invalid ACL path '$param->{path}'" }) if !$path;

        if (!$param->{delete} && !PVE::AccessControl::check_path($path)) {
            raise_param_exc({ path => "invalid ACL path '$param->{path}'" });
        }

        PVE::AccessControl::lock_user_config(
            sub {
                my $cfg = cfs_read_file("user.cfg");

                my $rpcenv = PVE::RPCEnvironment::get();
                my $authuser = $rpcenv->get_user();
                my $auth_user_privs = $rpcenv->permissions($authuser, $path);

                my $propagate = 1;

                if (defined($param->{propagate})) {
                    $propagate = $param->{propagate} ? 1 : 0;
                }

                my $node = PVE::AccessControl::find_acl_tree_node($cfg->{acl_root}, $path);

                foreach my $role (split_list($param->{roles})) {
                    die "role '$role' does not exist\n"
                        if !$cfg->{roles}->{$role};

                    # permissions() returns set privs as key, and propagate bit as value!
                    if (!defined($auth_user_privs->{'Permissions.Modify'})) {
                        # 'perm-modify' allows /vms/* with VM.Allocate and similar restricted use cases
                        # filter those to only allow handing out a subset of currently active privs
                        my $role_privs = $cfg->{roles}->{$role};
                        my $verb = $param->{delete} ? 'remove' : 'add';
                        foreach my $priv (keys $role_privs->%*) {
                            raise_param_exc(
                                {
                                    role =>
                                        "Cannot $verb role '$role' - requires 'Permissions.Modify' or superset of privileges.",
                                },
                            ) if !defined($auth_user_privs->{$priv});

                            # propagation is only potentially problematic for adding ACLs, not removing..
                            raise_param_exc(
                                {
                                    role =>
                                        "Cannot $verb role '$role' with propagation - requires 'Permissions.Modify' or propagated superset of privileges.",
                                },
                                )
                                if $propagate
                                && $auth_user_privs->{$priv} != $propagate
                                && !$param->{delete};
                        }

                        # NoAccess has no privs, needs an explicit check
                        raise_param_exc(
                            {
                                role =>
                                    "Cannot $verb role '$role' - requires 'Permissions.Modify'",
                            },
                        ) if $role eq 'NoAccess';
                    }

                    foreach my $group (split_list($param->{groups})) {

                        die "group '$group' does not exist\n"
                            if !$cfg->{groups}->{$group};

                        if ($param->{delete}) {
                            delete($node->{groups}->{$group}->{$role});
                        } else {
                            $node->{groups}->{$group}->{$role} = $propagate;
                        }
                    }

                    foreach my $userid (split_list($param->{users})) {
                        my $username = PVE::AccessControl::verify_username($userid);

                        die "user '$username' does not exist\n"
                            if !$cfg->{users}->{$username};

                        if ($param->{delete}) {
                            delete($node->{users}->{$username}->{$role});
                        } else {
                            $node->{users}->{$username}->{$role} = $propagate;
                        }
                    }

                    foreach my $tokenid (split_list($param->{tokens})) {
                        my ($username, $token) = PVE::AccessControl::split_tokenid($tokenid);
                        PVE::AccessControl::check_token_exist($cfg, $username, $token);

                        if ($param->{delete}) {
                            delete $node->{tokens}->{$tokenid}->{$role};
                        } else {
                            $node->{tokens}->{$tokenid}->{$role} = $propagate;
                        }
                    }
                }

                cfs_write_file("user.cfg", $cfg);
            },
            "ACL update failed",
        );

        return undef;
    },
});

1;

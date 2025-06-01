package PVE::API2::User;

use strict;
use warnings;

use PVE::Exception qw(raise raise_perm_exc raise_param_exc);
use PVE::Cluster qw (cfs_read_file cfs_write_file);
use PVE::Tools qw(split_list extract_param);
use PVE::JSONSchema qw(get_standard_option register_standard_option);
use PVE::SafeSyslog;

use PVE::AccessControl;
use PVE::Auth::Plugin;
use PVE::TokenConfig;

use PVE::RESTHandler;

use base qw(PVE::RESTHandler);

register_standard_option(
    'user-enable',
    {
        description =>
            "Enable the account (default). You can set this to '0' to disable the account",
        type => 'boolean',
        optional => 1,
        default => 1,
    },
);
register_standard_option(
    'user-expire',
    {
        description =>
            "Account expiration date (seconds since epoch). '0' means no expiration date.",
        type => 'integer',
        minimum => 0,
        optional => 1,
    },
);
register_standard_option('user-firstname', { type => 'string', optional => 1, maxLength => 1024 });
register_standard_option('user-lastname', { type => 'string', optional => 1, maxLength => 1024 });
register_standard_option(
    'user-email',
    {
        type => 'string',
        optional => 1,
        format => 'email-opt',
        maxLength => 254, # 256 including punctuation and separator is the max path as per RFC 5321
    },
);
register_standard_option(
    'user-comment',
    {
        type => 'string',
        optional => 1,
        maxLength => 2048,
    },
);
register_standard_option(
    'user-keys',
    {
        description => "Keys for two factor auth (yubico).",
        type => 'string',
        pattern => '[0-9a-zA-Z!=]{0,4096}',
        optional => 1,
    },
);
register_standard_option(
    'group-list',
    {
        type => 'string',
        format => 'pve-groupid-list',
        optional => 1,
        completion => \&PVE::AccessControl::complete_group,
    },
);
register_standard_option(
    'token-subid',
    {
        type => 'string',
        pattern => $PVE::AccessControl::token_subid_regex,
        description => 'User-specific token identifier.',
    },
);
register_standard_option(
    'token-expire',
    {
        description =>
            "API token expiration date (seconds since epoch). '0' means no expiration date.",
        type => 'integer',
        minimum => 0,
        optional => 1,
        default => 'same as user',
    },
);
register_standard_option(
    'token-privsep',
    {
        description =>
            "Restrict API token privileges with separate ACLs (default), or give full privileges of corresponding user.",
        type => 'boolean',
        optional => 1,
        default => 1,
    },
);
register_standard_option('token-comment', { type => 'string', optional => 1 });
register_standard_option(
    'token-info',
    {
        type => 'object',
        properties => {
            expire => get_standard_option('token-expire'),
            privsep => get_standard_option('token-privsep'),
            comment => get_standard_option('token-comment'),
        },
    },
);

my $token_info_extend = sub {
    my ($props) = @_;

    my $obj = get_standard_option('token-info');
    my $base_props = $obj->{properties};
    $obj->{properties} = {};

    foreach my $prop (keys %$base_props) {
        $obj->{properties}->{$prop} = $base_props->{$prop};
    }

    foreach my $add_prop (keys %$props) {
        $obj->{properties}->{$add_prop} = $props->{$add_prop};
    }

    return $obj;
};

my $extract_user_data = sub {
    my ($data, $full) = @_;

    my $res = {};

    foreach my $prop (qw(enable expire firstname lastname email comment keys)) {
        $res->{$prop} = $data->{$prop} if defined($data->{$prop});
    }

    return $res if !$full;

    $res->{groups} = $data->{groups} ? [sort keys %{ $data->{groups} }] : [];
    $res->{tokens} = $data->{tokens};

    return $res;
};

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    description => "User index.",
    permissions => {
        description =>
            "The returned list is restricted to users where you have 'User.Modify' or 'Sys.Audit' permissions on '/access/groups' or on a group the user belongs too. But it always includes the current (authenticated) user.",
        user => 'all',
    },
    protected => 1, # to access priv/tfa.cfg
    parameters => {
        additionalProperties => 0,
        properties => {
            enabled => {
                type => 'boolean',
                description => "Optional filter for enable property.",
                optional => 1,
            },
            full => {
                type => 'boolean',
                description => "Include group and token information.",
                optional => 1,
                default => 0,
            },
        },
    },
    returns => {
        type => 'array',
        items => {
            type => "object",
            properties => {
                userid => get_standard_option('userid-completed'),
                enable => get_standard_option('user-enable'),
                expire => get_standard_option('user-expire'),
                firstname => get_standard_option('user-firstname'),
                lastname => get_standard_option('user-lastname'),
                email => get_standard_option('user-email'),
                comment => get_standard_option('user-comment'),
                keys => get_standard_option('user-keys'),
                groups => get_standard_option('group-list'),
                tokens => {
                    type => 'array',
                    optional => 1,
                    items => $token_info_extend->({
                        tokenid => get_standard_option('token-subid'),
                    }),
                },
                'realm-type' => {
                    type => 'string',
                    format => 'pve-realm',
                    description => 'The type of the users realm',
                    optional => 1, # it should always be there, but we use conditional code below, so..
                },
                'totp-locked' => {
                    type => 'boolean',
                    optional => 1,
                    description => 'True if the user is currently locked out of TOTP factors.',
                },
                'tfa-locked-until' => {
                    type => 'integer',
                    optional => 1,
                    description =>
                        'Contains a timestamp until when a user is locked out of 2nd factors.',
                },
            },
        },
        links => [{ rel => 'child', href => "{userid}" }],
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $usercfg = $rpcenv->{user_cfg};
        my $authuser = $rpcenv->get_user();

        my $domainscfg = cfs_read_file('domains.cfg');
        my $domainids = $domainscfg->{ids};

        my $res = [];

        my $privs = ['User.Modify', 'Sys.Audit'];
        my $canUserMod = $rpcenv->check_any($authuser, "/access/groups", $privs, 1);
        my $groups = $rpcenv->filter_groups($authuser, $privs, 1);
        my $allowed_users = $rpcenv->group_member_join([keys %$groups]);

        my $tfa_cfg = cfs_read_file('priv/tfa.cfg');

        foreach my $user (sort keys %{ $usercfg->{users} }) {
            if (!($canUserMod || $user eq $authuser)) {
                next if !$allowed_users->{$user};
            }

            my $entry = $extract_user_data->($usercfg->{users}->{$user}, $param->{full});

            if (defined($param->{enabled})) {
                next if $entry->{enable} && !$param->{enabled};
                next if !$entry->{enable} && $param->{enabled};
            }

            $entry->{groups} = join(',', @{ $entry->{groups} }) if $entry->{groups};

            if (defined(my $tokens = $entry->{tokens})) {
                $entry->{tokens} =
                    [map { { tokenid => $_, %{ $tokens->{$_} } } } sort keys %$tokens];
            }

            if ($user =~ /($PVE::Auth::Plugin::realm_regex)$/) {
                my $realm = $1;
                $entry->{'realm-type'} = $domainids->{$realm}->{type}
                    if exists $domainids->{$realm};
            }

            $entry->{userid} = $user;

            if (defined($tfa_cfg)) {
                if (my $data = $tfa_cfg->tfa_lock_status($user)) {
                    for (qw(totp-locked tfa-locked-until)) {
                        $entry->{$_} = $data->{$_} if exists($data->{$_});
                    }
                }
            }

            push @$res, $entry;
        }

        return $res;
    },
});

__PACKAGE__->register_method({
    name => 'create_user',
    protected => 1,
    path => '',
    method => 'POST',
    permissions => {
        description =>
            "You need 'Realm.AllocateUser' on '/access/realm/<realm>' on the realm of user <userid>, and 'User.Modify' permissions to '/access/groups/<group>' for any group specified (or 'User.Modify' on '/access/groups' if you pass no groups.",
        check => [
            'and',
            ['userid-param', 'Realm.AllocateUser'],
            ['userid-group', ['User.Modify'], groups_param => 'create'],
        ],
    },
    description => "Create new user.",
    parameters => {
        additionalProperties => 0,
        properties => {
            userid => get_standard_option('userid-completed'),
            enable => get_standard_option('user-enable'),
            expire => get_standard_option('user-expire'),
            firstname => get_standard_option('user-firstname'),
            lastname => get_standard_option('user-lastname'),
            email => get_standard_option('user-email'),
            comment => get_standard_option('user-comment'),
            keys => get_standard_option('user-keys'),
            password => {
                description => "Initial password.",
                type => 'string',
                optional => 1,
                minLength => 8,
                maxLength => 64,
            },
            groups => get_standard_option('group-list'),
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        PVE::AccessControl::lock_user_config(
            sub {
                my ($username, $ruid, $realm) =
                    PVE::AccessControl::verify_username($param->{userid});

                my $usercfg = cfs_read_file("user.cfg");

                # ensure "user exists" check works for case insensitive realms
                $username = PVE::AccessControl::lookup_username($username, 1);
                die "user '$username' already exists\n" if $usercfg->{users}->{$username};

                PVE::AccessControl::domain_set_password($realm, $ruid, $param->{password})
                    if defined($param->{password});

                my $enable = defined($param->{enable}) ? $param->{enable} : 1;
                $usercfg->{users}->{$username} = { enable => $enable };
                $usercfg->{users}->{$username}->{expire} = $param->{expire} if $param->{expire};

                if ($param->{groups}) {
                    foreach my $group (split_list($param->{groups})) {
                        if ($usercfg->{groups}->{$group}) {
                            PVE::AccessControl::add_user_group($username, $usercfg, $group);
                        } else {
                            die "no such group '$group'\n";
                        }
                    }
                }

                $usercfg->{users}->{$username}->{firstname} = $param->{firstname}
                    if $param->{firstname};
                $usercfg->{users}->{$username}->{lastname} = $param->{lastname}
                    if $param->{lastname};
                $usercfg->{users}->{$username}->{email} = $param->{email} if $param->{email};
                $usercfg->{users}->{$username}->{comment} = $param->{comment}
                    if $param->{comment};
                $usercfg->{users}->{$username}->{keys} = $param->{keys} if $param->{keys};

                cfs_write_file("user.cfg", $usercfg);
            },
            "create user failed",
        );

        return undef;
    },
});

__PACKAGE__->register_method({
    name => 'read_user',
    path => '{userid}',
    method => 'GET',
    description => "Get user configuration.",
    permissions => {
        check => ['userid-group', ['User.Modify', 'Sys.Audit']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            userid => get_standard_option('userid-completed'),
        },
    },
    returns => {
        additionalProperties => 0,
        properties => {
            enable => get_standard_option('user-enable'),
            expire => get_standard_option('user-expire'),
            firstname => get_standard_option('user-firstname'),
            lastname => get_standard_option('user-lastname'),
            email => get_standard_option('user-email'),
            comment => get_standard_option('user-comment'),
            keys => get_standard_option('user-keys'),
            groups => {
                type => 'array',
                optional => 1,
                items => {
                    type => 'string',
                    format => 'pve-groupid',
                },
            },
            tokens => {
                optional => 1,
                type => 'object',
                additionalProperties => get_standard_option('token-info'),
            },
        },
        type => "object",
    },
    code => sub {
        my ($param) = @_;

        my ($username, undef, $domain) = PVE::AccessControl::verify_username($param->{userid});

        my $usercfg = cfs_read_file("user.cfg");

        my $data = PVE::AccessControl::check_user_exist($usercfg, $username);

        return &$extract_user_data($data, 1);
    },
});

__PACKAGE__->register_method({
    name => 'update_user',
    protected => 1,
    path => '{userid}',
    method => 'PUT',
    permissions => {
        check => ['userid-group', ['User.Modify'], groups_param => 'update'],
    },
    description => "Update user configuration.",
    parameters => {
        additionalProperties => 0,
        properties => {
            userid => get_standard_option('userid-completed'),
            enable => get_standard_option('user-enable'),
            expire => get_standard_option('user-expire'),
            firstname => get_standard_option('user-firstname'),
            lastname => get_standard_option('user-lastname'),
            email => get_standard_option('user-email'),
            comment => get_standard_option('user-comment'),
            keys => get_standard_option('user-keys'),
            groups => get_standard_option('group-list'),
            append => {
                type => 'boolean',
                optional => 1,
                requires => 'groups',
            },
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my ($username, $ruid, $realm) = PVE::AccessControl::verify_username($param->{userid});

        PVE::AccessControl::lock_user_config(
            sub {
                my $usercfg = cfs_read_file("user.cfg");

                PVE::AccessControl::check_user_exist($usercfg, $username);

                $usercfg->{users}->{$username}->{enable} = $param->{enable}
                    if defined($param->{enable});
                $usercfg->{users}->{$username}->{expire} = $param->{expire}
                    if defined($param->{expire});

                PVE::AccessControl::delete_user_group($username, $usercfg)
                    if (!$param->{append} && defined($param->{groups}));

                if ($param->{groups}) {
                    foreach my $group (split_list($param->{groups})) {
                        if ($usercfg->{groups}->{$group}) {
                            PVE::AccessControl::add_user_group($username, $usercfg, $group);
                        } else {
                            die "no such group '$group'\n";
                        }
                    }
                }

                $usercfg->{users}->{$username}->{firstname} = $param->{firstname}
                    if defined($param->{firstname});
                $usercfg->{users}->{$username}->{lastname} = $param->{lastname}
                    if defined($param->{lastname});
                $usercfg->{users}->{$username}->{email} = $param->{email}
                    if defined($param->{email});
                $usercfg->{users}->{$username}->{comment} = $param->{comment}
                    if defined($param->{comment});
                $usercfg->{users}->{$username}->{keys} = $param->{keys}
                    if defined($param->{keys});

                cfs_write_file("user.cfg", $usercfg);
            },
            "update user failed",
        );

        return undef;
    },
});

__PACKAGE__->register_method({
    name => 'delete_user',
    protected => 1,
    path => '{userid}',
    method => 'DELETE',
    description => "Delete user.",
    permissions => {
        check => [
            'and', ['userid-param', 'Realm.AllocateUser'], ['userid-group', ['User.Modify']],
        ],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            userid => get_standard_option('userid-completed'),
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();

        my ($userid, $ruid, $realm) = PVE::AccessControl::verify_username($param->{userid});

        PVE::AccessControl::lock_user_config(
            sub {
                my $usercfg = cfs_read_file("user.cfg");

                # NOTE: disable the user first (transaction like), so if (e.g.) we fail in the middle of
                # TFA deletion the user will be still disabled and not just without TFA protection.
                $usercfg->{users}->{$userid}->{enable} = 0;
                cfs_write_file("user.cfg", $usercfg);

                my $domain_cfg = cfs_read_file('domains.cfg');
                if (my $cfg = $domain_cfg->{ids}->{$realm}) {
                    my $plugin = PVE::Auth::Plugin->lookup($cfg->{type});
                    $plugin->delete_user($cfg, $realm, $ruid);
                }

                # Remove user from cache before removing the TFA entry so realms with TFA-enforcement
                # know that it's OK to drop any TFA entry in that case.
                delete $usercfg->{users}->{$userid};

                my $partial_deletion = '';
                eval {
                    PVE::AccessControl::user_remove_tfa($userid);
                    $partial_deletion = ' - but deleted related TFA';

                    PVE::AccessControl::delete_user_group($userid, $usercfg);
                    $partial_deletion .= ', Groups';
                    PVE::AccessControl::delete_user_acl($userid, $usercfg);
                    $partial_deletion .= ', ACLs';

                    cfs_write_file("user.cfg", $usercfg);
                };
                die "$@$partial_deletion\n" if $@;
            },
            "delete user failed",
        );

        return undef;
    },
});

__PACKAGE__->register_method({
    name => 'read_user_tfa_type',
    path => '{userid}/tfa',
    method => 'GET',
    protected => 1,
    description => "Get user TFA types (Personal and Realm).",
    permissions => {
        check => [
            'or', ['userid-param', 'self'], ['userid-group', ['User.Modify', 'Sys.Audit']],
        ],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            userid => get_standard_option('userid-completed'),
            multiple => {
                type => 'boolean',
                description => 'Request all entries as an array.',
                optional => 1,
                default => 0,
            },
        },
    },
    returns => {
        additionalProperties => 0,
        properties => {
            realm => {
                type => 'string',
                enum => [qw(oath yubico)],
                description => "The type of TFA the users realm has set, if any.",
                optional => 1,
            },
            user => {
                type => 'string',
                enum => [qw(oath u2f)],
                description => "The type of TFA the user has set, if any."
                    . " Only set if 'multiple' was not passed.",
                optional => 1,
            },
            types => {
                type => 'array',
                description => "Array of the user configured TFA types, if any."
                    . " Only available if 'multiple' was not passed.",
                optional => 1,
                items => {
                    type => 'string',
                    enum => [qw(totp u2f yubico webauthn recovedry)],
                    description => 'A TFA type.',
                },
            },
        },
        type => "object",
    },
    code => sub {
        my ($param) = @_;

        my ($username, undef, $realm) = PVE::AccessControl::verify_username($param->{userid});

        my $domain_cfg = cfs_read_file('domains.cfg');
        my $realm_cfg = $domain_cfg->{ids}->{$realm};
        die "auth domain '$realm' does not exist\n" if !$realm_cfg;

        my $res = {};
        my $realm_tfa = {};
        $realm_tfa = PVE::Auth::Plugin::parse_tfa_config($realm_cfg->{tfa})
            if $realm_cfg->{tfa};
        $res->{realm} = $realm_tfa->{type} if $realm_tfa->{type};

        my $tfa_cfg = cfs_read_file('priv/tfa.cfg');
        if ($param->{multiple}) {
            my $tfa = $tfa_cfg->get_user($username);
            my $user = [];
            foreach my $type (keys %$tfa) {
                next if !scalar($tfa->{$type}->@*);
                push @$user, $type;
            }
            $res->{user} = $user;
        } else {
            my $tfa = $tfa_cfg->{users}->{$username};
            $res->{user} = $tfa->{type} if $tfa->{type};
        }
        return $res;
    },
});

__PACKAGE__->register_method({
    name => 'unlock_tfa',
    path => '{userid}/unlock-tfa',
    method => 'PUT',
    protected => 1,
    description => "Unlock a user's TFA authentication.",
    permissions => {
        check => ['userid-group', ['User.Modify']],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            userid => get_standard_option('userid-completed'),
        },
    },
    returns => { type => 'boolean' },
    code => sub {
        my ($param) = @_;

        my $userid = extract_param($param, "userid");

        my $user_was_locked = PVE::AccessControl::lock_tfa_config(sub {
            my $tfa_cfg = cfs_read_file('priv/tfa.cfg');
            my $was_locked = $tfa_cfg->api_unlock_tfa($userid);
            cfs_write_file('priv/tfa.cfg', $tfa_cfg)
                if $was_locked;
            return $was_locked;
        });

        return $user_was_locked;
    },
});

__PACKAGE__->register_method({
    name => 'token_index',
    path => '{userid}/token',
    method => 'GET',
    description => "Get user API tokens.",
    permissions => {
        check => [
            'or', ['userid-param', 'self'], ['userid-group', ['User.Modify']],
        ],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            userid => get_standard_option('userid-completed'),
        },
    },
    returns => {
        type => "array",
        items => $token_info_extend->({
            tokenid => get_standard_option('token-subid'),
        }),
        links => [{ rel => 'child', href => "{tokenid}" }],
    },
    code => sub {
        my ($param) = @_;

        my $userid = PVE::AccessControl::verify_username($param->{userid});
        my $usercfg = cfs_read_file("user.cfg");

        my $user = PVE::AccessControl::check_user_exist($usercfg, $userid);

        my $tokens = $user->{tokens} // {};
        return [map { $tokens->{$_}->{tokenid} = $_; $tokens->{$_} } keys %$tokens];
    },
});

__PACKAGE__->register_method({
    name => 'read_token',
    path => '{userid}/token/{tokenid}',
    method => 'GET',
    description => "Get specific API token information.",
    permissions => {
        check => [
            'or', ['userid-param', 'self'], ['userid-group', ['User.Modify']],
        ],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            userid => get_standard_option('userid-completed'),
            tokenid => get_standard_option('token-subid'),
        },
    },
    returns => get_standard_option('token-info'),
    code => sub {
        my ($param) = @_;

        my $userid = PVE::AccessControl::verify_username($param->{userid});
        my $tokenid = $param->{tokenid};

        my $usercfg = cfs_read_file("user.cfg");

        return PVE::AccessControl::check_token_exist($usercfg, $userid, $tokenid);
    },
});

__PACKAGE__->register_method({
    name => 'generate_token',
    path => '{userid}/token/{tokenid}',
    method => 'POST',
    description =>
        "Generate a new API token for a specific user. NOTE: returns API token value, which needs to be stored as it cannot be retrieved afterwards!",
    protected => 1,
    permissions => {
        check => [
            'or', ['userid-param', 'self'], ['userid-group', ['User.Modify']],
        ],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            userid => get_standard_option('userid-completed'),
            tokenid => get_standard_option('token-subid'),
            expire => get_standard_option('token-expire'),
            privsep => get_standard_option('token-privsep'),
            comment => get_standard_option('token-comment'),
        },
    },
    returns => {
        additionalProperties => 0,
        type => "object",
        properties => {
            info => get_standard_option('token-info'),
            value => {
                type => 'string',
                description => 'API token value used for authentication.',
            },
            'full-tokenid' => {
                type => 'string',
                format_description => '<userid>!<tokenid>',
                description => 'The full token id.',
            },
        },
    },
    code => sub {
        my ($param) = @_;

        my $userid = PVE::AccessControl::verify_username(extract_param($param, 'userid'));
        my $tokenid = extract_param($param, 'tokenid');

        my $usercfg = cfs_read_file("user.cfg");

        my $token = PVE::AccessControl::check_token_exist($usercfg, $userid, $tokenid, 1);
        my ($full_tokenid, $value);

        PVE::AccessControl::check_user_exist($usercfg, $userid);
        raise_param_exc({ 'tokenid' => 'Token already exists.' }) if defined($token);

        my $generate_and_add_token = sub {
            $usercfg = cfs_read_file("user.cfg");
            PVE::AccessControl::check_user_exist($usercfg, $userid);
            die "Token already exists.\n"
                if defined(PVE::AccessControl::check_token_exist($usercfg, $userid, $tokenid, 1));

            $full_tokenid = PVE::AccessControl::join_tokenid($userid, $tokenid);
            $value = PVE::TokenConfig::generate_token($full_tokenid);

            $token = {};
            $token->{privsep} = defined($param->{privsep}) ? $param->{privsep} : 1;
            $token->{expire} = $param->{expire} if defined($param->{expire});
            $token->{comment} = $param->{comment} if $param->{comment};

            $usercfg->{users}->{$userid}->{tokens}->{$tokenid} = $token;
            cfs_write_file("user.cfg", $usercfg);
        };

        PVE::AccessControl::lock_user_config($generate_and_add_token,
            'generating token failed');

        return {
            info => $token,
            value => $value,
            'full-tokenid' => $full_tokenid,
        };
    },
});

__PACKAGE__->register_method({
    name => 'update_token_info',
    path => '{userid}/token/{tokenid}',
    method => 'PUT',
    description => "Update API token for a specific user.",
    protected => 1,
    permissions => {
        check => [
            'or', ['userid-param', 'self'], ['userid-group', ['User.Modify']],
        ],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            userid => get_standard_option('userid-completed'),
            tokenid => get_standard_option('token-subid'),
            expire => get_standard_option('token-expire'),
            privsep => get_standard_option('token-privsep'),
            comment => get_standard_option('token-comment'),
        },
    },
    returns =>
        get_standard_option('token-info', { description => "Updated token information." }),
    code => sub {
        my ($param) = @_;

        my $userid = PVE::AccessControl::verify_username(extract_param($param, 'userid'));
        my $tokenid = extract_param($param, 'tokenid');

        my $usercfg = cfs_read_file("user.cfg");
        my $token = PVE::AccessControl::check_token_exist($usercfg, $userid, $tokenid);

        PVE::AccessControl::lock_user_config(
            sub {
                $usercfg = cfs_read_file("user.cfg");
                $token = PVE::AccessControl::check_token_exist($usercfg, $userid, $tokenid);

                my $full_tokenid = PVE::AccessControl::join_tokenid($userid, $tokenid);

                $token->{privsep} = $param->{privsep} if defined($param->{privsep});
                $token->{expire} = $param->{expire} if defined($param->{expire});
                $token->{comment} = $param->{comment} if $param->{comment};

                $usercfg->{users}->{$userid}->{tokens}->{$tokenid} = $token;
                cfs_write_file("user.cfg", $usercfg);
            },
            'updating token info failed',
        );

        return $token;
    },
});

__PACKAGE__->register_method({
    name => 'remove_token',
    path => '{userid}/token/{tokenid}',
    method => 'DELETE',
    description => "Remove API token for a specific user.",
    protected => 1,
    permissions => {
        check => [
            'or', ['userid-param', 'self'], ['userid-group', ['User.Modify']],
        ],
    },
    parameters => {
        additionalProperties => 0,
        properties => {
            userid => get_standard_option('userid-completed'),
            tokenid => get_standard_option('token-subid'),
        },
    },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;

        my $userid = PVE::AccessControl::verify_username(extract_param($param, 'userid'));
        my $tokenid = extract_param($param, 'tokenid');

        my $usercfg = cfs_read_file("user.cfg");
        my $token = PVE::AccessControl::check_token_exist($usercfg, $userid, $tokenid);

        PVE::AccessControl::lock_user_config(
            sub {
                $usercfg = cfs_read_file("user.cfg");

                PVE::AccessControl::check_token_exist($usercfg, $userid, $tokenid);

                my $full_tokenid = PVE::AccessControl::join_tokenid($userid, $tokenid);
                PVE::TokenConfig::delete_token($full_tokenid);
                delete $usercfg->{users}->{$userid}->{tokens}->{$tokenid};

                cfs_write_file("user.cfg", $usercfg);
            },
            'deleting token failed',
        );

        return;
    },
});
1;

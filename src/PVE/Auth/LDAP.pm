package PVE::Auth::LDAP;

use strict;
use warnings;

use PVE::Auth::Plugin;
use PVE::JSONSchema;
use PVE::LDAP;
use PVE::Tools;

use base qw(PVE::Auth::Plugin);

sub type {
    return 'ldap';
}

sub properties {
    return {
        base_dn => {
            description => "LDAP base domain name",
            type => 'string',
            optional => 1,
            maxLength => 256,
        },
        user_attr => {
            description => "LDAP user attribute name",
            type => 'string',
            pattern => '\S{2,}',
            optional => 1,
            maxLength => 256,
        },
        bind_dn => {
            description => "LDAP bind domain name",
            type => 'string',
            optional => 1,
            maxLength => 256,
        },
        password => {
            description =>
                "LDAP bind password. Will be stored in '/etc/pve/priv/realm/<REALM>.pw'.",
            type => 'string',
            optional => 1,
        },
        verify => {
            description => "Verify the server's SSL certificate",
            type => 'boolean',
            optional => 1,
            default => 0,
        },
        capath => {
            description => "Path to the CA certificate store",
            type => 'string',
            optional => 1,
            default => '/etc/ssl/certs',
        },
        cert => {
            description => "Path to the client certificate",
            type => 'string',
            optional => 1,
        },
        certkey => {
            description => "Path to the client certificate key",
            type => 'string',
            optional => 1,
        },
        filter => {
            description => "LDAP filter for user sync.",
            type => 'string',
            optional => 1,
            maxLength => 2048,
        },
        sync_attributes => {
            description => "Comma separated list of key=value pairs for specifying"
                . " which LDAP attributes map to which PVE user field. For example,"
                . " to map the LDAP attribute 'mail' to PVEs 'email', write "
                . " 'email=mail'. By default, each PVE user field is represented "
                . " by an LDAP attribute of the same name.",
            optional => 1,
            type => 'string',
            pattern => '\w+=[^,]+(,\s*\w+=[^,]+)*',
        },
        user_classes => {
            description => "The objectclasses for users.",
            type => 'string',
            default => 'inetorgperson, posixaccount, person, user',
            format => 'ldap-simple-attr-list',
            optional => 1,
        },
        group_dn => {
            description => "LDAP base domain name for group sync. If not set, the"
                . " base_dn will be used.",
            type => 'string',
            optional => 1,
            maxLength => 256,
        },
        group_name_attr => {
            description => "LDAP attribute representing a groups name. If not set"
                . " or found, the first value of the DN will be used as name.",
            type => 'string',
            format => 'ldap-simple-attr',
            optional => 1,
            maxLength => 256,
        },
        group_filter => {
            description => "LDAP filter for group sync.",
            type => 'string',
            optional => 1,
            maxLength => 2048,
        },
        group_classes => {
            description => "The objectclasses for groups.",
            type => 'string',
            default => 'groupOfNames, group, univentionGroup, ipausergroup',
            format => 'ldap-simple-attr-list',
            optional => 1,
        },
        'sync-defaults-options' => {
            description => "The default options for behavior of synchronizations.",
            type => 'string',
            format => 'realm-sync-options',
            optional => 1,
        },
        mode => {
            description => "LDAP protocol mode.",
            type => 'string',
            enum => ['ldap', 'ldaps', 'ldap+starttls'],
            optional => 1,
            default => 'ldap',
        },
        'case-sensitive' => {
            description => "username is case-sensitive",
            type => 'boolean',
            optional => 1,
            default => 1,
        },
    };
}

sub options {
    return {
        server1 => {},
        server2 => { optional => 1 },
        base_dn => {},
        bind_dn => { optional => 1 },
        password => { optional => 1 },
        user_attr => {},
        port => { optional => 1 },
        secure => { optional => 1 },
        sslversion => { optional => 1 },
        default => { optional => 1 },
        comment => { optional => 1 },
        tfa => { optional => 1 },
        verify => { optional => 1 },
        capath => { optional => 1 },
        cert => { optional => 1 },
        certkey => { optional => 1 },
        filter => { optional => 1 },
        sync_attributes => { optional => 1 },
        user_classes => { optional => 1 },
        group_dn => { optional => 1 },
        group_name_attr => { optional => 1 },
        group_filter => { optional => 1 },
        group_classes => { optional => 1 },
        'sync-defaults-options' => { optional => 1 },
        mode => { optional => 1 },
        'case-sensitive' => { optional => 1 },
    };
}

my sub verify_sync_attribute_value {
    my ($attr, $value) = @_;

    # The attribute does not include the realm, so can't use PVE::Auth::Plugin::verify_username
    if ($attr eq 'username') {
        die "value '$value' does not look like a valid user name\n"
            if $value !~ m/${PVE::Auth::Plugin::user_regex}/;
        return;
    }

    return if $attr eq 'enable'; # for backwards compat, don't parse/validate

    if (my $schema = PVE::JSONSchema::get_standard_option("user-$attr")) {
        PVE::JSONSchema::validate($value, $schema, "invalid value '$value'\n");
    } else {
        die "internal error: no schema for attribute '$attr' with value '$value' available!\n";
    }
}

sub get_scheme_and_port {
    my ($class, $config) = @_;

    my $scheme = $config->{mode} // ($config->{secure} ? 'ldaps' : 'ldap');

    my $default_port = $scheme eq 'ldaps' ? 636 : 389;
    my $port = $config->{port} // $default_port;

    return ($scheme, $port);
}

sub connect_and_bind {
    my ($class, $config, $realm, $param) = @_;

    my $servers = [$config->{server1}];
    push @$servers, $config->{server2} if $config->{server2};

    my ($scheme, $port) = $class->get_scheme_and_port($config);

    my %ldap_args;
    if ($config->{verify}) {
        $ldap_args{verify} = 'require';
        $ldap_args{clientcert} = $config->{cert} if $config->{cert};
        $ldap_args{clientkey} = $config->{certkey} if $config->{certkey};
        if (defined(my $capath = $config->{capath})) {
            if (-d $capath) {
                $ldap_args{capath} = $capath;
            } else {
                $ldap_args{cafile} = $capath;
            }
        }
    } else {
        $ldap_args{verify} = 'none';
    }

    if ($scheme ne 'ldap') {
        $ldap_args{sslversion} = $config->{sslversion} || 'tlsv1_2';
    }

    my $ldap = PVE::LDAP::ldap_connect($servers, $scheme, $port, \%ldap_args);

    if ($config->{bind_dn}) {
        my $bind_dn = $config->{bind_dn};
        my $bind_pass = $param->{password} || ldap_get_credentials($realm);
        die "missing password for realm $realm\n" if !defined($bind_pass);
        PVE::LDAP::ldap_bind($ldap, $bind_dn, $bind_pass);
    } elsif ($config->{cert} && $config->{certkey}) {
        warn "skipping anonymous bind with clientcert\n";
    } else {
        PVE::LDAP::ldap_bind($ldap);
    }

    if (!$config->{base_dn}) {
        my $root = $ldap->root_dse(attrs => ['defaultNamingContext']);
        $config->{base_dn} = $root->get_value('defaultNamingContext');
    }

    return $ldap;
}

# returns:
# {
#     'username@realm' => {
# 	'attr1' => 'value1',
# 	'attr2' => 'value2',
# 	...
#     },
#     ...
# }
#
# or in list context:
# (
#     {
# 	'username@realm' => {
# 	    'attr1' => 'value1',
# 	    'attr2' => 'value2',
# 	    ...
# 	},
# 	...
#     },
#     {
# 	'uid=username,dc=....' => 'username@realm',
# 	...
#     }
# )
# the map of dn->username is needed for group membership sync
sub get_users {
    my ($class, $config, $realm) = @_;

    my $ldap = $class->connect_and_bind($config, $realm);

    my $user_name_attr = $config->{user_attr} // 'uid';
    my $ldap_attribute_map = {
        $user_name_attr => 'username',
        enable => 'enable',
        expire => 'expire',
        firstname => 'firstname',
        lastname => 'lastname',
        email => 'email',
        comment => 'comment',
        keys => 'keys',
        # NOTE: also ensure verify_sync_attribute_value can handle any new/changed attribute name
    };
    # build on the fly as this is small and only called once per realm in a ldap-sync anyway
    my $valid_sync_attributes = { map { $_ => 1 } values $ldap_attribute_map->%* };

    foreach my $attr (PVE::Tools::split_list($config->{sync_attributes})) {
        my ($ours, $ldap) = ($attr =~ m/^\s*(\w+)=(.*)\s*$/);
        if (!$valid_sync_attributes->{$ours}) {
            warn "skipping bad 'sync_attributes' entry – '$ours' is not a valid target attribute\n";
            next;
        }
        $ldap_attribute_map->{$ldap} = $ours;
    }

    my $filter = $config->{filter};
    my $basedn = $config->{base_dn};

    $config->{user_classes} //= 'inetorgperson, posixaccount, person, user';
    my $classes = [PVE::Tools::split_list($config->{user_classes})];

    my $users =
        PVE::LDAP::query_users($ldap, $filter, [keys %$ldap_attribute_map], $basedn, $classes);

    my $ret = {};
    my $dnmap = {};

    foreach my $user (@$users) {
        my $user_attributes = $user->{attributes};
        my $userid = $user_attributes->{$user_name_attr}->[0];
        my $username = "$userid\@$realm";

        # we cannot sync usernames that do not meet our criteria
        eval { PVE::Auth::Plugin::verify_username($username) };
        if (my $err = $@) {
            warn "$err";
            next;
        }

        $ret->{$username} = {};

        foreach my $attr (keys %$user_attributes) {
            if (my $ours = $ldap_attribute_map->{$attr}) {
                my $value = $user_attributes->{$attr}->[0];
                eval { verify_sync_attribute_value($ours, $value) };
                if (my $err = $@) {
                    warn "skipping attribute mapping '$attr'->'$ours' for user '$username' - $err";
                    next;
                }
                $ret->{$username}->{$ours} = $value;
            }
        }

        if (wantarray) {
            my $dn = $user->{dn};
            $dnmap->{ lc($dn) } = $username;
        }
    }

    return wantarray ? ($ret, $dnmap) : $ret;
}

# needs a map for dn -> username, we get this from the get_users call
# otherwise we cannot determine the group membership
sub get_groups {
    my ($class, $config, $realm, $dnmap) = @_;

    my $filter = $config->{group_filter};
    my $basedn = $config->{group_dn} // $config->{base_dn};
    my $attr = $config->{group_name_attr};
    $config->{group_classes} //= 'groupOfNames, group, univentionGroup, ipausergroup';
    my $classes = [PVE::Tools::split_list($config->{group_classes})];

    my $ldap = $class->connect_and_bind($config, $realm);

    my $groups = PVE::LDAP::query_groups($ldap, $basedn, $classes, $filter, $attr);

    my $ret = {};

    foreach my $group (@$groups) {
        my $name = $group->{name};
        if (!$name && $group->{dn} =~ m/^[^=]+=([^,]+),/) {
            $name = PVE::Tools::trim($1);
        }
        if ($name) {
            $name .= "-$realm";

            # we cannot sync groups that do not meet our criteria
            eval { PVE::AccessControl::verify_groupname($name) };
            if (my $err = $@) {
                warn "$err";
                next;
            }

            $ret->{$name} = { users => {} };
            foreach my $member (@{ $group->{members} }) {
                if (my $user = $dnmap->{ lc($member) }) {
                    $ret->{$name}->{users}->{$user} = 1;
                }
            }
        }
    }

    return $ret;
}

sub authenticate_user {
    my ($class, $config, $realm, $username, $password) = @_;

    my $ldap = $class->connect_and_bind($config, $realm);

    my $user_dn =
        PVE::LDAP::get_user_dn($ldap, $username, $config->{user_attr}, $config->{base_dn});
    PVE::LDAP::auth_user_dn($ldap, $user_dn, $password);

    $ldap->unbind();
    return 1;
}

my $ldap_pw_dir = "/etc/pve/priv/realm";

sub ldap_cred_file_name {
    my ($realmid) = @_;
    return "${ldap_pw_dir}/${realmid}.pw";
}

sub get_cred_file {
    my ($realmid) = @_;

    my $cred_file = ldap_cred_file_name($realmid);
    if (-e $cred_file) {
        return $cred_file;
    } elsif (-e "/etc/pve/priv/ldap/${realmid}.pw") {
        # FIXME: remove fallback with 7.0 by doing a rename on upgrade from 6.x
        return "/etc/pve/priv/ldap/${realmid}.pw";
    }

    return $cred_file;
}

sub ldap_set_credentials {
    my ($password, $realmid) = @_;

    my $cred_file = ldap_cred_file_name($realmid);
    mkdir $ldap_pw_dir;

    PVE::Tools::file_set_contents($cred_file, $password);

    return $cred_file;
}

sub ldap_get_credentials {
    my ($realmid) = @_;

    if (my $cred_file = get_cred_file($realmid)) {
        return PVE::Tools::file_read_firstline($cred_file);
    }
    return undef;
}

sub ldap_delete_credentials {
    my ($realmid) = @_;

    if (my $cred_file = get_cred_file($realmid)) {
        return if !-e $cred_file; # nothing to do
        unlink($cred_file) or warn "removing LDAP credentials '$cred_file' failed: $!\n";
    }
}

sub on_add_hook {
    my ($class, $realm, $config, %param) = @_;

    if (defined($param{password})) {
        ldap_set_credentials($param{password}, $realm);
    } else {
        ldap_delete_credentials($realm);
    }
}

sub on_update_hook {
    my ($class, $realm, $config, %param) = @_;

    return if !exists($param{password});

    if (defined($param{password})) {
        ldap_set_credentials($param{password}, $realm);
    } else {
        ldap_delete_credentials($realm);
    }
}

sub on_delete_hook {
    my ($class, $realm, $config) = @_;

    ldap_delete_credentials($realm);
}

sub check_connection {
    my ($class, $realm, $config, %param) = @_;

    $class->connect_and_bind($config, $realm, \%param);
}

1;

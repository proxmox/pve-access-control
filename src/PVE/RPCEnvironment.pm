package PVE::RPCEnvironment;

use strict;
use warnings;

use PVE::AccessControl;
use PVE::Cluster;
use PVE::Exception qw(raise raise_param_exc raise_perm_exc);
use PVE::INotify;
use PVE::ProcFSTools;
use PVE::RESTEnvironment;
use PVE::SafeSyslog;
use PVE::Tools;

use base qw(PVE::RESTEnvironment);

# ACL cache

my $compile_acl_path = sub {
    my ($self, $user, $path) = @_;

    my $cfg = $self->{user_cfg};

    return undef if !$cfg->{roles};

    # permissions() has an early return for this case
    die "internal error" if $user eq 'root@pam';

    my $cache = $self->{aclcache};
    $cache->{$user} = {} if !$cache->{$user};
    my $data = $cache->{$user};

    # permissions() will always prime the cache for the owning user
    my ($username, undef) = PVE::AccessControl::split_tokenid($user, 1);
    die "internal error"
        if $username && $username ne 'root@pam' && !defined($cache->{$username});

    # resolve and cache roles of the current user/token for all pool ACL paths
    if (!$data->{poolroles}) {
        $data->{poolroles} = {};

        foreach my $pool (keys %{ $cfg->{pools} }) {
            my $d = $cfg->{pools}->{$pool};
            my $pool_roles = PVE::AccessControl::roles($cfg, $user, "/pool/$pool"); # pool roles
            next if !scalar(keys %$pool_roles);
            foreach my $vmid (keys %{ $d->{vms} }) {
                for my $role (keys %$pool_roles) {
                    $data->{poolroles}->{"/vms/$vmid"}->{$role} = 1;
                }
            }
            foreach my $storeid (keys %{ $d->{storage} }) {
                for my $role (keys %$pool_roles) {
                    $data->{poolroles}->{"/storage/$storeid"}->{$role} = 1;
                }
            }
        }
    }

    # get roles of current user/token on checked path - this already handles
    # propagation and NoAccess along the path
    #
    # hash mapping role name to propagation flag value, a key being defined
    # means the role is set
    my $roles = PVE::AccessControl::roles($cfg, $user, $path);

    # apply roles inherited from pools
    if ($data->{poolroles}->{$path}) {
        # NoAccess must not be trumped by pool ACLs
        if (!defined($roles->{NoAccess})) {
            if ($data->{poolroles}->{$path}->{NoAccess}) {
                # but pool ACL NoAccess trumps regular ACL
                $roles = { 'NoAccess' => 0 };
            } else {
                foreach my $role (keys %{ $data->{poolroles}->{$path} }) {
                    # only use role from pool ACL if regular ACL didn't already
                    # set it, and never set propagation for pool-derived ACLs
                    $roles->{$role} = 0 if !defined($roles->{$role});
                }
            }
        }
    }

    # cache roles
    $data->{roles}->{$path} = $roles;

    # derive privs from set roles - hash mapping privilege name to propagation
    # flag value, a key being defined means the priv is set
    my $privs = {};
    foreach my $role (keys %$roles) {
        if (my $privset = $cfg->{roles}->{$role}) {
            foreach my $p (keys %$privset) {
                # set priv '$p' to propagated iff any of the set roles
                # containing it have the propagated flag set
                $privs->{$p} ||= $roles->{$role};
            }
        }
    }

    # intersect user and token permissions
    if ($username && $username ne 'root@pam') {
        # map of set privs to their propagation flag value, for the owning user
        my $user_privs = $cache->{$username}->{privs}->{$path};
        # list of privs set both for token and owning user
        my $filtered_privs = [grep { defined($user_privs->{$_}) } keys %$privs];
        # intersection of privs using filtered list, combining both propagation
        # flags
        $privs = { map { $_ => $user_privs->{$_} && $privs->{$_} } @$filtered_privs };
    }

    foreach my $priv (keys %$privs) {
        # safeguard, this should never happen anyway
        delete $privs->{$priv} if !defined($privs->{$priv});
    }

    # cache privs
    $data->{privs}->{$path} = $privs;

    return $privs;
};

# this is the method used by permission check helpers below
#
# returned value is a hash mapping all set privileges on $path to their
# respective propagation flag. the propagation flag is informational only -
# actual propagation is handled in PVE::AccessControl::roles(). to determine
# whether a privilege is set, check for definedness in the returned hash.
#
# compiled ACLs are cached, so repeated checks for the same path and user are
# almost free.
#
# if $user is a tokenid, permissions are calculated depending on the
# privilege-separation flag value:
# - non-priv-separated: permissions for owning user are returned
# - priv-separated: permissions for owning user are calculated and intersected
#   with those of token
sub permissions {
    my ($self, $user, $path) = @_;

    if ($user eq 'root@pam') { # root can do anything
        my $cfg = $self->{user_cfg};
        return { map { $_ => 1 } keys %{ $cfg->{roles}->{'Administrator'} } };
    }

    if (!defined($path)) {
        # this shouldn't happen!
        warn "internal error: ACL check called for undefined ACL path!\n";
        return {};
    }

    if (PVE::AccessControl::pve_verify_tokenid($user, 1)) {
        my ($username, $token) = PVE::AccessControl::split_tokenid($user);
        my $cfg = $self->{user_cfg};
        my $token_info = $cfg->{users}->{$username}->{tokens}->{$token};

        return {} if !$token_info;

        # ensure cache for user is populated
        my $user_perms = $self->permissions($username, $path);

        # return user privs for non-privsep tokens
        return $user_perms if !$token_info->{privsep};
    } else {
        $user = PVE::AccessControl::verify_username($user, 1);
        return {} if !$user;
    }

    my $cache = $self->{aclcache};
    $cache->{$user} = {} if !$cache->{$user};

    my $acl = $cache->{$user};

    my $perm = $acl->{privs}->{$path};
    return $perm if $perm;

    return &$compile_acl_path($self, $user, $path);
}

sub compute_api_permission {
    my ($self, $authuser) = @_;

    my $usercfg = $self->{user_cfg};

    my $res = {};
    my $priv_re_map = {
        vms => qr/VM\.|Permissions\.Modify/,
        access => qr/(User|Group)\.|Permissions\.Modify/,
        storage => qr/Datastore\.|Permissions\.Modify/,
        nodes => qr/Sys\.|Permissions\.Modify/,
        sdn => qr/SDN\.|Permissions\.Modify/,
        dc => qr/Sys\.Audit|Sys\.Modify|SDN\./,
        mapping => qr/Mapping\.|Permissions.Modify/,
    };
    map { $res->{$_} = {} } keys %$priv_re_map;

    my $required_paths = ['/', '/nodes', '/access/groups', '/vms', '/storage', '/sdn', '/mapping'];
    my $defined_paths = [];
    PVE::AccessControl::iterate_acl_tree(
        "/",
        $usercfg->{acl_root},
        sub {
            my ($path, $node) = @_;
            push @$defined_paths, $path;
        },
    );

    my $checked_paths = {};
    foreach my $path (@$required_paths, @$defined_paths) {
        next if $checked_paths->{$path};
        $checked_paths->{$path} = 1;

        my $path_perm = $self->permissions($authuser, $path);

        my $toplevel = ($path =~ /^\/(\w+)/) ? $1 : 'dc';
        if ($toplevel eq 'pool') {
            foreach my $priv (keys %$path_perm) {
                next if !defined($path_perm->{$priv});

                if ($priv =~ m/^VM\./) {
                    $res->{vms}->{$priv} = 1;
                } elsif ($priv =~ m/^Datastore\./) {
                    $res->{storage}->{$priv} = 1;
                } elsif ($priv eq 'Permissions.Modify') {
                    $res->{storage}->{$priv} = 1;
                    $res->{vms}->{$priv} = 1;
                }
            }
        } else {
            my $priv_regex = $priv_re_map->{$toplevel} // next;
            foreach my $priv (keys %$path_perm) {
                next if !defined($path_perm->{$priv});

                next if $priv !~ m/^($priv_regex)/;
                $res->{$toplevel}->{$priv} = 1;
            }
        }
    }

    return $res;
}

sub get_effective_permissions {
    my ($self, $user) = @_;

    # default / top level paths
    my $paths = {
        '/' => 1,
        '/access' => 1,
        '/access/groups' => 1,
        '/nodes' => 1,
        '/pool' => 1,
        '/sdn' => 1,
        '/storage' => 1,
        '/vms' => 1,
    };

    my $cfg = $self->{user_cfg};

    # paths explicitly listed in ACLs
    PVE::AccessControl::iterate_acl_tree(
        "/",
        $cfg->{acl_root},
        sub {
            my ($path, $node) = @_;
            $paths->{$path} = 1;
        },
    );

    # paths referenced by pool definitions
    foreach my $pool (keys %{ $cfg->{pools} }) {
        my $d = $cfg->{pools}->{$pool};
        foreach my $vmid (keys %{ $d->{vms} }) {
            $paths->{"/vms/$vmid"} = 1;
        }
        foreach my $storeid (keys %{ $d->{storage} }) {
            $paths->{"/storage/$storeid"} = 1;
        }
    }

    my $perms = {};
    foreach my $path (keys %$paths) {
        my $path_perms = $self->permissions($user, $path);
        foreach my $priv (keys %$path_perms) {
            delete $path_perms->{$priv} if !defined($path_perms->{$priv});
        }
        # filter paths where user has NO permissions
        $perms->{$path} = $path_perms if %$path_perms;
    }
    return $perms;
}

sub check {
    my ($self, $user, $path, $privs, $noerr) = @_;

    my $perm = $self->permissions($user, $path);

    foreach my $priv (@$privs) {
        PVE::AccessControl::verify_privname($priv);
        if (!defined($perm->{$priv})) {
            return undef if $noerr;
            raise_perm_exc("$path, $priv");
        }
    }

    return 1;
}

sub check_any {
    my ($self, $user, $path, $privs, $noerr) = @_;

    my $perm = $self->permissions($user, $path);

    my $found = 0;
    foreach my $priv (@$privs) {
        PVE::AccessControl::verify_privname($priv);
        if (defined($perm->{$priv})) {
            $found = 1;
            last;
        }
    }

    return 1 if $found;

    return undef if $noerr;

    raise_perm_exc("$path, " . join("|", @$privs));
}

sub check_full {
    my ($self, $username, $path, $privs, $any, $noerr) = @_;
    if ($any) {
        return $self->check_any($username, $path, $privs, $noerr);
    } else {
        return $self->check($username, $path, $privs, $noerr);
    }
}

# check for any fashion of access to vnet/bridge
sub check_sdn_bridge {
    my ($self, $username, $zone, $bridge, $privs, $noerr) = @_;

    my $path = "/sdn/zones/$zone/$bridge";
    # check access to bridge itself
    return 1 if $self->check_any($username, $path, $privs, 1);

    my $cfg = $self->{user_cfg};
    my $bridge_acl = PVE::AccessControl::find_acl_tree_node($cfg->{acl_root}, $path);
    if ($bridge_acl) {
        # check access to VLANs
        my $vlans = $bridge_acl->{children};
        for my $vlan (keys %$vlans) {
            my $vlanpath = "$path/$vlan";
            return 1 if $self->check_any($username, $vlanpath, $privs, 1);
        }
    }

    # repeat check, but fatal
    $self->check_any($username, $path, $privs, 0) if !$noerr;

    return;
}

sub check_user_enabled {
    my ($self, $user, $noerr) = @_;

    my $cfg = $self->{user_cfg};
    return PVE::AccessControl::check_user_enabled($cfg, $user, $noerr);
}

sub check_user_exist {
    my ($self, $user, $noerr) = @_;

    my $cfg = $self->{user_cfg};
    return PVE::AccessControl::check_user_exist($cfg, $user, $noerr);
}

sub check_pool_exist {
    my ($self, $pool, $noerr) = @_;

    my $cfg = $self->{user_cfg};

    return 1 if $cfg->{pools}->{$pool};

    return undef if $noerr;

    raise_perm_exc("pool '$pool' does not exist");
}

sub check_vm_perm {
    my ($self, $user, $vmid, $pool, $privs, $any, $noerr) = @_;

    my $cfg = $self->{user_cfg};

    if ($pool) {
        return if $self->check_full($user, "/pool/$pool", $privs, $any, 1);
    }
    return $self->check_full($user, "/vms/$vmid", $privs, $any, $noerr);
}

sub is_group_member {
    my ($self, $group, $user) = @_;

    my $cfg = $self->{user_cfg};

    return 0 if !$cfg->{groups}->{$group};

    return defined($cfg->{groups}->{$group}->{users}->{$user});
}

sub filter_groups {
    my ($self, $user, $privs, $any) = @_;

    my $cfg = $self->{user_cfg};

    my $groups = {};
    foreach my $group (keys %{ $cfg->{groups} }) {
        my $path = "/access/groups/$group";
        if ($self->check_full($user, $path, $privs, $any, 1)) {
            $groups->{$group} = $cfg->{groups}->{$group};
        }
    }

    return $groups;
}

sub group_member_join {
    my ($self, $grouplist) = @_;

    my $users = {};

    my $cfg = $self->{user_cfg};
    foreach my $group (@$grouplist) {
        my $data = $cfg->{groups}->{$group};
        next if !$data;
        foreach my $user (keys %{ $data->{users} }) {
            $users->{$user} = 1;
        }
    }

    return $users;
}

sub check_perm_modify {
    my ($self, $username, $path, $noerr) = @_;

    return $self->check($username, '/access', ['Permissions.Modify'], $noerr) if !$path;

    my $testperms = ['Permissions.Modify'];
    if ($path =~ m|^/storage/.+$|) {
        push @$testperms, 'Datastore.Allocate';
    } elsif ($path =~ m|^/vms/.+$|) {
        push @$testperms, 'VM.Allocate';
    } elsif ($path =~ m|^/pool/.+$|) {
        push @$testperms, 'Pool.Allocate';
    }

    return $self->check_any($username, $path, $testperms, $noerr);
}

sub exec_api2_perm_check {
    my ($self, $check, $username, $param, $noerr) = @_;

    # syslog("info", "CHECK " . join(', ', @$check));

    my $ind = 0;
    my $test = $check->[$ind++];
    die "no permission test specified" if !$test;

    if ($test eq 'and') {
        while (my $subcheck = $check->[$ind++]) {
            $self->exec_api2_perm_check($subcheck, $username, $param);
        }
        return 1;
    } elsif ($test eq 'or') {
        while (my $subcheck = $check->[$ind++]) {
            return 1 if $self->exec_api2_perm_check($subcheck, $username, $param, 1);
        }
        return 0 if $noerr;
        raise_perm_exc();
    } elsif ($test eq 'perm') {
        my ($t, $tmplpath, $privs, %options) = @$check;
        my $any = $options{any};
        die "missing parameters" if !($tmplpath && $privs);
        my $require_param = $options{require_param};
        if ($require_param && !defined($param->{$require_param})) {
            return 0 if $noerr;
            raise_perm_exc();
        }
        my $path = PVE::Tools::template_replace($tmplpath, $param);
        my $normpath = PVE::AccessControl::normalize_path($path);
        warn "Failed to normalize '$path'\n" if !defined($normpath) && defined($path);

        return $self->check_full($username, $normpath, $privs, $any, $noerr);
    } elsif ($test eq 'userid-group') {
        my $userid = $param->{userid};
        my ($t, $privs, %options) = @$check;

        my $check_existing_user = !$options{groups_param} || $options{groups_param} ne 'create';
        return 0 if $check_existing_user && !$self->check_user_exist($userid, $noerr);

        # check permission for ALL groups (and thus ALL users)
        if (!$self->check_any($username, "/access/groups", $privs, 1)) {
            # list of groups $username has any of $privs on
            my $groups = $self->filter_groups($username, $privs, 1);
            if ($options{groups_param}) {
                # does $username have any of $privs on all new/updated/.. groups?
                my @group_param = PVE::Tools::split_list($param->{groups});
                raise_perm_exc("/access/groups, " . join("|", @$privs)) if !scalar(@group_param);
                foreach my $pg (@group_param) {
                    raise_perm_exc("/access/groups/$pg, " . join("|", @$privs))
                        if !$groups->{$pg};
                }
            }
            if ($check_existing_user) {
                # does $username have any of $privs on any existing group of $userid
                my $allowed_users = $self->group_member_join([keys %$groups]);
                if (!$allowed_users->{$userid}) {
                    return 0 if $noerr;
                    raise_perm_exc();
                }
            }
        }
        return 1;
    } elsif ($test eq 'userid-param') {
        my ($userid, undef, $realm) = PVE::AccessControl::verify_username($param->{userid});
        my ($t, $subtest) = @$check;
        die "missing parameters" if !$subtest;
        if ($subtest eq 'self') {
            return 0 if !$self->check_user_exist($userid, $noerr);
            return 1 if $username eq $userid;
            return 0 if $noerr;
            raise_perm_exc();
        } elsif ($subtest eq 'Realm.AllocateUser') {
            my $path = "/access/realm/$realm";
            return $self->check($username, $path, ['Realm.AllocateUser'], $noerr);
        } else {
            die "unknown userid-param test";
        }
    } elsif ($test eq 'perm-modify') {
        my ($t, $tmplpath) = @$check;
        my $path = PVE::Tools::template_replace($tmplpath, $param);
        $path = PVE::AccessControl::normalize_path($path);
        return 0 if !defined($path); # should already die in API2::ACL
        return $self->check_perm_modify($username, $path, $noerr);
    } else {
        die "unknown permission test";
    }
}

sub check_api2_permissions {
    my ($self, $perm, $username, $param) = @_;

    return 1 if !$username && $perm->{user} && $perm->{user} eq 'world';

    raise_perm_exc("user != null") if !$username;

    return 1 if $username eq 'root@pam';

    raise_perm_exc('user != root@pam') if !$perm;

    return 1 if $perm->{user} && $perm->{user} eq 'all';

    return $self->exec_api2_perm_check($perm->{check}, $username, $param)
        if $perm->{check};

    raise_perm_exc();
}

sub log_cluster_msg {
    my ($self, $pri, $user, $msg) = @_;

    PVE::Cluster::log_msg($pri, $user, $msg);
}

sub broadcast_tasklist {
    my ($self, $tlist) = @_;

    PVE::Cluster::broadcast_tasklist($tlist);
}

# initialize environment - must be called once at program startup
sub init {
    my ($class, $type, %params) = @_;

    $class = ref($class) || $class;

    my $self = $class->SUPER::init($type, %params);

    $self->{user_cfg} = {};
    $self->{aclcache} = {};
    $self->{aclversion} = undef;

    return $self;
}

# init_request - must be called before each RPC request
sub init_request {
    my ($self, %params) = @_;

    PVE::Cluster::cfs_update();

    $self->{result_attributes} = {};

    my $userconfig; # we use this for regression tests
    foreach my $p (keys %params) {
        if ($p eq 'userconfig') {
            $userconfig = $params{$p};
        } else {
            die "unknown parameter '$p'";
        }
    }

    eval {
        $self->{aclcache} = {};
        if ($userconfig) {
            my $ucdata = PVE::Tools::file_get_contents($userconfig);
            my $cfg = PVE::AccessControl::parse_user_config($userconfig, $ucdata);
            $self->{user_cfg} = $cfg;
        } else {
            my $ucvers = PVE::Cluster::cfs_file_version('user.cfg');
            if (
                !$self->{aclcache}
                || !defined($self->{aclversion})
                || !defined($ucvers)
                || ($ucvers ne $self->{aclversion})
            ) {
                $self->{aclversion} = $ucvers;
                my $cfg = PVE::Cluster::cfs_read_file('user.cfg');
                $self->{user_cfg} = $cfg;
            }
        }
    };
    if (my $err = $@) {
        $self->{user_cfg} = {};
        die "Unable to load access control list: $err";
    }
}

# hacks: to provide better backwards compatibility

# old code uses PVE::RPCEnvironment::get();
# new code should use PVE::RPCEnvironment->get();
sub get {
    return PVE::RESTEnvironment->get();
}

# old code uses PVE::RPCEnvironment::is_worker();
# new code should use PVE::RPCEnvironment->is_worker();
sub is_worker {
    return PVE::RESTEnvironment->is_worker();
}

# Permission helper for TFA and password API endpoints modifying users.
# Only root may modify root, regular users need to specify their password.
#
# Returns the same as `verify_username` in list context (userid, ruid, realm),
# or just the userid in scalar context.
sub reauth_user_for_user_modification : prototype($$$$;$) {
    my ($rpcenv, $authuser, $userid, $password, $param_name) = @_;

    $param_name //= 'password';

    ($userid, my $ruid, my $realm) = PVE::AccessControl::verify_username($userid);
    $rpcenv->check_user_exist($userid);

    raise_perm_exc() if $userid eq 'root@pam' && $authuser ne 'root@pam';

    # Regular users need to confirm their password to change TFA settings.
    if ($authuser ne 'root@pam') {
        raise_param_exc({ $param_name => 'password is required to modify user' })
            if !defined($password);

        ($authuser, my $auth_username, my $auth_realm) =
            PVE::AccessControl::verify_username($authuser);

        my $domain_cfg = PVE::Cluster::cfs_read_file('domains.cfg');
        my $cfg = $domain_cfg->{ids}->{$auth_realm};
        die "auth domain '$auth_realm' does not exist\n" if !$cfg;
        my $plugin = PVE::Auth::Plugin->lookup($cfg->{type});
        $plugin->authenticate_user($cfg, $auth_realm, $auth_username, $password);
    }

    return wantarray ? ($userid, $ruid, $realm) : $userid;
}

1;

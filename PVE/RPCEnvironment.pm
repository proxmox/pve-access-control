package PVE::RPCEnvironment;

use strict;
use warnings;

use PVE::RESTEnvironment;

use PVE::Exception qw(raise raise_perm_exc);
use PVE::SafeSyslog;
use PVE::Tools;
use PVE::INotify;
use PVE::Cluster;
use PVE::ProcFSTools;
use PVE::AccessControl;

use base qw(PVE::RESTEnvironment);

# ACL cache

my $compile_acl_path = sub {
    my ($self, $user, $path) = @_;

    my $cfg = $self->{user_cfg};

    return undef if !$cfg->{roles};

    die "internal error" if $user eq 'root@pam';

    my $cache = $self->{aclcache};
    $cache->{$user} = {} if !$cache->{$user};
    my $data = $cache->{$user};

    if (!$data->{poolroles}) {
	$data->{poolroles} = {};

	foreach my $pool (keys %{$cfg->{pools}}) {
	    my $d = $cfg->{pools}->{$pool};
	    my @ra = PVE::AccessControl::roles($cfg, $user, "/pool/$pool"); # pool roles
	    next if !scalar(@ra);
	    foreach my $vmid (keys %{$d->{vms}}) {
		for my $role (@ra) {
		    $data->{poolroles}->{"/vms/$vmid"}->{$role} = 1;
		}
	    }
	    foreach my $storeid (keys %{$d->{storage}}) {
		for my $role (@ra) {
		    $data->{poolroles}->{"/storage/$storeid"}->{$role} = 1;
		}
	    }
	}
    }

    my @ra = PVE::AccessControl::roles($cfg, $user, $path);

    # apply roles inherited from pools
    # Note: assume we do not want to propagate those privs
    if ($data->{poolroles}->{$path}) {
	if (!($ra[0] && $ra[0] eq 'NoAccess')) {
	    if ($data->{poolroles}->{$path}->{NoAccess}) {
		@ra = ('NoAccess');
	    } else {
		foreach my $role (keys %{$data->{poolroles}->{$path}}) {
		    push @ra, $role;
		}
	    }
	}
    }

    $data->{roles}->{$path} = [ @ra ];

    my $privs = {};
    foreach my $role (@ra) {
	if (my $privset = $cfg->{roles}->{$role}) {
	    foreach my $p (keys %$privset) {
		$privs->{$p} = 1;
	    }
	}
    }
    $data->{privs}->{$path} = $privs;

    return $privs;
};

sub roles {
   my ($self, $user, $path) = @_;

   if ($user eq 'root@pam') { # root can do anything
       return ('Administrator');
   }

   $user = PVE::AccessControl::verify_username($user, 1);
   return () if !$user;

   my $cache = $self->{aclcache};
   $cache->{$user} = {} if !$cache->{$user};

   my $acl = $cache->{$user};

   my $roles = $acl->{roles}->{$path};
   return @$roles if $roles;

   &$compile_acl_path($self, $user, $path);
   $roles = $acl->{roles}->{$path} || [];
   return @$roles;
}

sub permissions {
    my ($self, $user, $path) = @_;

    if ($user eq 'root@pam') { # root can do anything
	my $cfg = $self->{user_cfg};
	return $cfg->{roles}->{'Administrator'};
    }

    $user = PVE::AccessControl::verify_username($user, 1);
    return {} if !$user;

    my $cache = $self->{aclcache};
    $cache->{$user} = {} if !$cache->{$user};

    my $acl = $cache->{$user};

    my $perm = $acl->{privs}->{$path};
    return $perm if $perm;

    return &$compile_acl_path($self, $user, $path);
}

sub check {
    my ($self, $user, $path, $privs, $noerr) = @_;

    my $perm = $self->permissions($user, $path);

    foreach my $priv (@$privs) {
	PVE::AccessControl::verify_privname($priv);
	if (!$perm->{$priv}) {
	    return undef if $noerr;
	    raise_perm_exc("$path, $priv");
	}
    };

    return 1;
};

sub check_any {
    my ($self, $user, $path, $privs, $noerr) = @_;

    my $perm = $self->permissions($user, $path);

    my $found = 0;
    foreach my $priv (@$privs) {
	PVE::AccessControl::verify_privname($priv);
	if ($perm->{$priv}) {
	    $found = 1;
	    last;
	}
    };

    return 1 if $found;

    return undef if $noerr;

    raise_perm_exc("$path, " . join("|", @$privs));
};

sub check_full {
    my ($self, $username, $path, $privs, $any, $noerr) = @_;
    if ($any) {
	return $self->check_any($username, $path, $privs, $noerr);
    } else {
	return $self->check($username, $path, $privs, $noerr);
    }
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
};

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
    foreach my $group (keys %{$cfg->{groups}}) {
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
	foreach my $user (keys %{$data->{users}}) {
	    $users->{$user} = 1;
	}
    }

    return $users;
}

sub check_perm_modify {
    my ($self, $username, $path, $noerr) = @_;

    return $self->check($username, '/access', [ 'Permissions.Modify' ], $noerr) if !$path;

    my $testperms = [ 'Permissions.Modify' ];
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
	$path = PVE::AccessControl::normalize_path($path);
	return $self->check_full($username, $path, $privs, $any, $noerr);
    } elsif ($test eq 'userid-group') {
	my $userid = $param->{userid};
	my ($t, $privs, %options) = @$check;
	return 0 if !$options{groups_param} && !$self->check_user_exist($userid, $noerr);
	if (!$self->check_any($username, "/access/groups", $privs, 1)) {
	    my $groups = $self->filter_groups($username, $privs, 1);
	    if ($options{groups_param}) {
		my @group_param = PVE::Tools::split_list($param->{groups});
		raise_perm_exc("/access/groups, " . join("|", @$privs)) if !scalar(@group_param);
		foreach my $pg (@group_param) {
		    raise_perm_exc("/access/groups/$pg, " . join("|", @$privs))
			if !$groups->{$pg};
		}
	    } else {
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
	    my $path =  "/access/realm/$realm";
	    return $self->check($username, $path, ['Realm.AllocateUser'], $noerr);
	} else {
	    die "unknown userid-param test";
	}
     } elsif ($test eq 'perm-modify') {
	my ($t, $tmplpath) = @$check;
	my $path = PVE::Tools::template_replace($tmplpath, $param);
	$path = PVE::AccessControl::normalize_path($path);
	return $self->check_perm_modify($username, $path, $noerr);
   } else {
	die "unknown permission test";
    }
};

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
};


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
	    if (!$self->{aclcache} || !defined($self->{aclversion}) ||
		!defined($ucvers) ||  ($ucvers ne $self->{aclversion})) {
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

# hacks: to provide better backwards compatibiliy

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

1;

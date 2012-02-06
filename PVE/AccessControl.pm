package PVE::AccessControl;

use strict;
use Encode;
use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;
use MIME::Base64;
use Digest::SHA;
use Authen::PAM qw(:constants);
use Net::LDAP;
use PVE::Tools qw(run_command lock_file file_get_contents split_list safe_print);
use PVE::Cluster qw(cfs_register_file cfs_read_file cfs_write_file cfs_lock_file);
use PVE::JSONSchema;
use Encode;

use Data::Dumper; # fixme: remove

# $authdir must be writable by root only!
my $confdir = "/etc/pve";
my $authdir = "$confdir/priv";
my $authprivkeyfn = "$authdir/authkey.key";
my $authpubkeyfn = "$confdir/authkey.pub";
my $shadowconfigfile = "priv/shadow.cfg";
my $domainconfigfile = "domains.cfg";
my $pve_www_key_fn = "$confdir/pve-www.key";

my $ticket_lifetime = 3600*2; # 2 hours

Crypt::OpenSSL::RSA->import_random_seed();

cfs_register_file('user.cfg', 
		  \&parse_user_config,  
		  \&write_user_config);

cfs_register_file($shadowconfigfile, 
		  \&parse_shadow_passwd, 
		  \&write_shadow_config);

cfs_register_file($domainconfigfile, 
		  \&parse_domains,
		  \&write_domains);


sub lock_user_config {
    my ($code, $errmsg) = @_;

    cfs_lock_file("user.cfg", undef, $code);
    my $err = $@;
    if ($err) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }
}

sub lock_domain_config {
    my ($code, $errmsg) = @_;

    cfs_lock_file($domainconfigfile, undef, $code);
    my $err = $@;
    if ($err) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }
}

sub lock_shadow_config {
    my ($code, $errmsg) = @_;

    cfs_lock_file($shadowconfigfile, undef, $code);
    my $err = $@;
    if ($err) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }
}

my $pve_auth_pub_key;
sub get_pubkey {    

    return $pve_auth_pub_key if $pve_auth_pub_key;

    my $input = PVE::Tools::file_get_contents($authpubkeyfn); 

    $pve_auth_pub_key = Crypt::OpenSSL::RSA->new_public_key($input);

    return $pve_auth_pub_key;
}

my $csrf_prevention_secret;
my $get_csrfr_secret = sub {
    if (!$csrf_prevention_secret) {
	my $input = PVE::Tools::file_get_contents($pve_www_key_fn); 
	$csrf_prevention_secret = Digest::SHA::sha1_base64($input);
    }
    return $csrf_prevention_secret;
};

sub assemble_csrf_prevention_token {
    my ($username) = @_;

    my $timestamp = sprintf("%08X", time());

    my $digest = Digest::SHA::sha1_base64("$timestamp:$username", &$get_csrfr_secret());

    return "$timestamp:$digest"; 
}

sub verify_csrf_prevention_token {
    my ($username, $token, $noerr) = @_;

    if ($token =~ m/^([A-Z0-9]{8}):(\S+)$/) {
	my $sig = $2;
	my $timestamp = $1;
	my $ttime = hex($timestamp);

	my $digest = Digest::SHA::sha1_base64("$timestamp:$username", &$get_csrfr_secret());

	my $age = time() - $ttime;
	return if ($digest eq $sig) && ($age > -300) && ($age < $ticket_lifetime);
    }

    die "Permission denied - invalid csrf token\n" if !$noerr;

    return undef;
}

my $pve_auth_priv_key;
sub get_privkey {

    return $pve_auth_priv_key if $pve_auth_priv_key;

    my $input = PVE::Tools::file_get_contents($authprivkeyfn); 

    $pve_auth_priv_key = Crypt::OpenSSL::RSA->new_private_key($input);

    return $pve_auth_priv_key;
}

sub assemble_ticket {
    my ($username) = @_;

    my $rsa_priv = get_privkey();

    my $timestamp = sprintf("%08X", time());

    my $plain = "PVE:$username:$timestamp";

    my $ticket = $plain . "::" . encode_base64($rsa_priv->sign($plain), '');

    return $ticket;
}

sub verify_ticket {
    my ($ticket, $noerr) = @_;

    if ($ticket && $ticket =~ m/^(PVE:\S+)::([^:\s]+)$/) {
	my $plain = $1;
	my $sig = $2;

	my $rsa_pub = get_pubkey();
	if ($rsa_pub->verify($plain, decode_base64($sig))) {
	    if ($plain =~ m/^PVE:(([A-Za-z0-9\.\-_]+)(\@([A-Za-z0-9\.\-_]+))?):([A-Z0-9]{8})$/) {
		my $username = $1;
		my $timestamp = $5;
		my $ttime = hex($timestamp);

		my $age = time() - $ttime;

		if (($age > -300) && ($age < $ticket_lifetime)) {
		    return wantarray ? ($username, $age) : $username;
		}
	    }
	}
    }

    die "permission denied - invalid ticket\n" if !$noerr;

    return undef;
}

# VNC tickets
# - they do not contain the username in plain text
# - they are restricted to a specific resource path (example: '/vms/100')
sub assemble_vnc_ticket {
    my ($username, $path) = @_;

    my $rsa_priv = get_privkey();

    my $timestamp = sprintf("%08X", time());

    my $plain = "PVEVNC:$timestamp";

    $path = normalize_path($path);

    my $full = "$plain:$username:$path";

    my $ticket = $plain . "::" . encode_base64($rsa_priv->sign($full), '');

    return $ticket;
}

sub verify_vnc_ticket {
    my ($ticket, $username, $path, $noerr) = @_;

    if ($ticket && $ticket =~ m/^(PVEVNC:\S+)::([^:\s]+)$/) {
	my $plain = $1;
	my $sig = $2;
	my $full = "$plain:$username:$path";

	my $rsa_pub = get_pubkey();
	# Note: sign only match if $username and  $path is correct
	if ($rsa_pub->verify($full, decode_base64($sig))) {
	    if ($plain =~ m/^PVEVNC:([A-Z0-9]{8})$/) {
		my $ttime = hex($1);

		my $age = time() - $ttime;

		if (($age > -20) && ($age < 40)) {
		    return 1;
		}
	    }
	}
    }

    die "permission denied - invalid vnc ticket\n" if !$noerr;

    return undef;
}


sub authenticate_user_shadow {
    my ($userid, $password) = @_;

    die "no password\n" if !$password;

    my $shadow_cfg = cfs_read_file($shadowconfigfile);
    
    if ($shadow_cfg->{users}->{$userid}) {
	my $encpw = crypt($password, $shadow_cfg->{users}->{$userid}->{shadow});
        die "invalid credentials\n" if ($encpw ne $shadow_cfg->{users}->{$userid}->{shadow});
    } else {
	die "no password set\n";
    }
}

sub authenticate_user_pam {
    my ($userid, $password) = @_;

    # user (www-data) need to be able to read /etc/passwd /etc/shadow

    die "no password\n" if !$password;

    my $pamh = new Authen::PAM ('common-auth', $userid, sub {
	my @res;
	while(@_) {
	    my $msg_type = shift;
	    my $msg = shift;
	    push @res, (0, $password);
	}
	push @res, 0;
	return @res;
    });

    if (!ref ($pamh)) {
	my $err = $pamh->pam_strerror($pamh);
	die "error during PAM init: $err";
    }

    my $res;

    if (($res = $pamh->pam_authenticate(0)) != PAM_SUCCESS) {
	my $err = $pamh->pam_strerror($res);
	die "$err\n";
    }

    if (($res = $pamh->pam_acct_mgmt (0)) != PAM_SUCCESS) {
	my $err = $pamh->pam_strerror($res);
	die "$err\n";
    }

    $pamh = 0; # call destructor
}

sub authenticate_user_ad {

    my ($entry, $server, $userid, $password) = @_;

    my $default_port = $entry->{secure} ? 636: 389;
    my $port = $entry->{port} ? $entry->{port} : $default_port;
    my $scheme = $entry->{secure} ? 'ldaps' : 'ldap';
    my $conn_string = "$scheme://${server}:$port";
    
    my $ldap = Net::LDAP->new($server) || die "$@\n";

    $userid = "$userid\@$entry->{domain}" 
	if $userid !~ m/@/ && $entry->{domain};

    my $res = $ldap->bind($userid, password => $password);

    my $code = $res->code();
    my $err = $res->error;

    $ldap->unbind();

    die "$err\n" if ($code);
}

sub authenticate_user_ldap {

    my ($entry, $server, $userid, $password) = @_;

    my $default_port = $entry->{secure} ? 636: 389;
    my $port = $entry->{port} ? $entry->{port} : $default_port;
    my $scheme = $entry->{secure} ? 'ldaps' : 'ldap';
    my $conn_string = "$scheme://${server}:$port";

    my $ldap = Net::LDAP->new($conn_string, verify => 'none') || die "$@\n";
    my $search = $entry->{user_attr} . "=" . $userid;
    my $result = $ldap->search( base    => "$entry->{base_dn}",
				scope   => "sub",
				filter  => "$search",
				attrs   => ['dn']
				);
    die "no entries returned\n" if !$result->entries;
    my @entries = $result->entries;
    my $res = $ldap->bind($entries[0]->dn, password => $password);

    my $code = $res->code();
    my $err = $res->error;

    $ldap->unbind();

    die "$err\n" if ($code);
}

sub authenticate_user_domain {
    my ($realm, $userid, $password) = @_;
 
    my $domain_cfg = cfs_read_file($domainconfigfile);

    die "no auth domain specified" if !$realm;

    if ($realm eq 'pam') {
	authenticate_user_pam($userid, $password);
	return;
    } 

    eval {
	if ($realm eq 'pve') {
	    authenticate_user_shadow($userid, $password);
	} else { 

	    my $cfg = $domain_cfg->{$realm};
	    die "auth domain '$realm' does not exists\n" if !$cfg;
    
	    if ($cfg->{type} eq 'ad') {
		eval { authenticate_user_ad($cfg, $cfg->{server1}, $userid, $password); };
		my $err = $@;
		return if !$err;
		die $err if !$cfg->{server2};
		authenticate_user_ad($cfg, $cfg->{server2}, $userid, $password); 
	    } elsif ($cfg->{type} eq 'ldap') {
		eval { authenticate_user_ldap($cfg, $cfg->{server1}, $userid, $password); };
		my $err = $@;
		return if !$err;
		die $err if !$cfg->{server2};
		authenticate_user_ldap($cfg, $cfg->{server2}, $userid, $password); 
	    } else {
		die "unknown auth type '$cfg->{type}'\n";
	    }
	}
    };
    if (my $err = $@) {
	sleep(2); # timeout after failed auth
	die $err;
    }
}

sub check_user_exist {
    my ($usercfg, $username, $noerr) = @_;

    $username = verify_username($username, $noerr);
    return undef if !$username;
 
    return $usercfg->{users}->{$username} if $usercfg && $usercfg->{users}->{$username};

    die "no such user ('$username')\n" if !$noerr;
 
    return undef;
}

sub check_user_enabled {
    my ($usercfg, $username, $noerr) = @_;

    my $data = check_user_exist($usercfg, $username, $noerr);
    return undef if !$data;

    return 1 if $data->{enable};

    return 1 if $username eq 'root@pam'; # root is always enabled

    die "user '$username' is disabled\n" if !$noerr;
 
    return undef;
}

# password should be utf8 encoded
sub authenticate_user {
    my ($username, $password) = @_;

    die "no username specified\n" if !$username;
 
    my ($userid, $realm);

    ($username, $userid, $realm) = verify_username($username);

    my $usercfg = cfs_read_file('user.cfg');

    eval { check_user_enabled($usercfg, $username); };
    if (my $err = $@) {
	sleep(2);
	die $err;
    }

    my $ctime = time();
    my $expire = $usercfg->{users}->{$username}->{expire};

    if ($expire && ($expire < $ctime)) {
	sleep(2);
	die "account expired\n"
    }

    authenticate_user_domain($realm, $userid, $password);

    return $username;
}

sub delete_shadow_password {
    my ($userid) = @_;
 
    lock_shadow_config(sub {
	my $shadow_cfg = cfs_read_file($shadowconfigfile);
	delete ($shadow_cfg->{users}->{$userid})
	    if $shadow_cfg->{users}->{$userid};
	cfs_write_file($shadowconfigfile, $shadow_cfg);
    });
}

sub store_shadow_password {
    my ($userid, $password) = @_;
  
    lock_shadow_config(sub {
	my $shadow_cfg = cfs_read_file($shadowconfigfile);
	$shadow_cfg->{users}->{$userid}->{shadow} = encrypt_pw($password);
	cfs_write_file($shadowconfigfile, $shadow_cfg);
    });
}

sub encrypt_pw {
    my ($pw) = @_;

    my $time = substr (Digest::SHA::sha1_base64 (time), 0, 8);
    return crypt (encode("utf8", $pw), "\$5\$$time\$");
}

sub store_pam_password {
    my ($userid, $password) = @_;

    my $cmd = ['/usr/sbin/usermod'];

    my $epw = encrypt_pw($password);
    push @$cmd, '-p', $epw;

    push @$cmd, $userid;

    run_command($cmd);
}

sub domain_set_password {
    my ($realm, $userid, $password) = @_;

    die "no auth domain specified" if !$realm;

    if ($realm eq 'pam') {
	store_pam_password($userid, $password);
    } elsif ($realm eq 'pve') {
	store_shadow_password($userid, $password);
    } else {
	die "can't set password on auth domain '$realm'\n";
    }
}

sub add_user_group {

    my ($username, $usercfg, $group) = @_;
    $usercfg->{users}->{$username}->{groups}->{$group} = 1;
    $usercfg->{groups}->{$group}->{users}->{$username} = 1;
}

sub delete_user_group {

    my ($username, $usercfg) = @_;
    
    foreach my $group (keys %{$usercfg->{groups}}) {

	delete ($usercfg->{groups}->{$group}->{users}->{$username}) 
	    if $usercfg->{groups}->{$group}->{users}->{$username};
    }
}

sub delete_user_acl {

    my ($username, $usercfg) = @_;

    foreach my $acl (keys %{$usercfg->{acl}}) {

	delete ($usercfg->{acl}->{$acl}->{users}->{$username}) 
	    if $usercfg->{acl}->{$acl}->{users}->{$username};
    }
}

sub delete_group_acl {

    my ($group, $usercfg) = @_;

    foreach my $acl (keys %{$usercfg->{acl}}) {

	delete ($usercfg->{acl}->{$acl}->{groups}->{$group}) 
	    if $usercfg->{acl}->{$acl}->{groups}->{$group};
    }
}

sub delete_pool_acl {

    my ($pool, $usercfg) = @_;

    my $path = "/pool/$pool";

    foreach my $aclpath (keys %{$usercfg->{acl}}) {
	delete ($usercfg->{acl}->{$aclpath})
	    if $usercfg->{acl}->{$aclpath} eq 'path';
    }
}

# we automatically create some predefined roles by splitting privs
# into 3 groups (per category)
# root: only root is allowed to do that
# admin: an administrator can to that
# user: a normak user/customer can to that
my $privgroups = {
    VM => {
	root => [],
	admin => [	     
	    'VM.Config.Disk', 
	    'VM.Config.CDROM', # change CDROM media
	    'VM.Config.CPU', 
	    'VM.Config.Memory', 
	    'VM.Config.Network', 
	    'VM.Config.HWType',
	    'VM.Config.Options', # covers all other things 
	    'VM.Allocate', 
	    'VM.Migrate',
	    'VM.Monitor', 
	],
	user => [
	    'VM.Console', 
	    'VM.PowerMgmt',
	],
	audit => [ 
	    'VM.Audit',
	],
    },
    Sys => {
	root => [
	    'Sys.PowerMgmt',	 
	    'Sys.Modify', # edit/change node settings
	],
	admin => [
	    'Permissions.Modify',
	    'Sys.Console',    
	    'Sys.Syslog',
	],
	user => [],
	audit => [
	    'Sys.Audit',
	],
    },
    Datastore => {
	root => [],
	admin => [
	    'Datastore.Allocate',
	    'Datastore.AllocateTemplate',
	],
	user => [
	    'Datastore.AllocateSpace',
	],
	audit => [
	    'Datastore.Audit',
	],
    },
    User => {
	root => [
	    'Realm.Allocate',
	],
	admin => [
	    'User.Modify',
	    'Group.Allocate', # edit/change group settings
	    'Realm.AllocateUser', 
	],
	user => [],
	audit => [],
    },
    Pool => {
	root => [],
	admin => [
	    'Pool.Allocate', # create/delete pools
	],
	user => [],
	audit => [],
    },
};

my $valid_privs = {};

my $special_roles = {
    'NoAccess' => {}, # no priviledges
    'Administrator' => $valid_privs, # all priviledges
};

sub create_roles {

    foreach my $cat (keys %$privgroups) {
	my $cd = $privgroups->{$cat};
	foreach my $p (@{$cd->{root}}, @{$cd->{admin}}, 
		       @{$cd->{user}}, @{$cd->{audit}}) {
	    $valid_privs->{$p} = 1;
	}
	foreach my $p (@{$cd->{admin}}, @{$cd->{user}}, @{$cd->{audit}}) {

	    $special_roles->{"PVE${cat}Admin"}->{$p} = 1;
	    $special_roles->{"PVEAdmin"}->{$p} = 1;
	}
	if (scalar(@{$cd->{user}})) {
	    foreach my $p (@{$cd->{user}}, @{$cd->{audit}}) {
		$special_roles->{"PVE${cat}User"}->{$p} = 1;
	    }
	}
	foreach my $p (@{$cd->{audit}}) {
	    $special_roles->{"PVEAuditor"}->{$p} = 1;
	}
    }
};

create_roles();

my $valid_attributes = {
    ad => {
	server1 => '[\w\d]+(.[\w\d]+)*',
	server2 => '[\w\d]+(.[\w\d]+)*',
	domain => '\S+',
	port => '\d+',
	secure => '',
	comment => '.*',
    },
    ldap => {
	server1 => '[\w\d]+(.[\w\d]+)*',
	server2 => '[\w\d]+(.[\w\d]+)*',
	base_dn => '\w+=[\w\s]+(,\s*\w+=[\w\s]+)*',
	user_attr => '\S{2,}',
	secure => '',
	port => '\d+',
	comment => '.*',
    }
};

sub add_role_privs {
    my ($role, $usercfg, $privs) = @_;

    return if !$privs;

    die "role '$role' does not exist\n" if !$usercfg->{roles}->{$role};

    foreach my $priv (split_list($privs)) {
	if (defined ($valid_privs->{$priv})) {
	    $usercfg->{roles}->{$role}->{$priv} = 1;
	} else {
	    die "invalid priviledge '$priv'\n";
	} 
    }	
}

sub normalize_path {
    my $path = shift;

    $path =~ s|/+|/|g;

    $path =~ s|/$||;

    $path = '/' if !$path;

    $path = "/$path" if $path !~ m|^/|;

    return undef if $path !~ m|^[[:alnum:]\-\_\/]+$|;

    return $path;
} 

my $realm_regex = qr/[A-Za-z][A-Za-z0-9\.\-_]+/;

sub pve_verify_realm {
    my ($realm, $noerr) = @_;
 
    if ($realm !~ m/^${realm_regex}$/) {
	return undef if $noerr;
	die "value does not look like a valid realm\n"; 
    }
    return $realm;
}

PVE::JSONSchema::register_format('pve-userid', \&verify_username);
sub verify_username {
    my ($username, $noerr) = @_;

    $username = '' if !$username;
    my $len = length($username);
    if ($len < 3) {
	die "user name '$username' is too short\n" if !$noerr;
	return undef;
    }
    if ($len > 64) {
	die "user name '$username' is too long ($len > 64)\n" if !$noerr;
	return undef;
    }

    # we only allow a limited set of characters (colon is not allowed,
    # because we store usernames in colon separated lists)!
    if ($username =~ m/^([^\s:]+)\@(${realm_regex})$/) {
	return wantarray ? ($username, $1, $2) : $username;
    }

    die "value '$username' does not look like a valid user name\n" if !$noerr;

    return undef;
}
PVE::JSONSchema::register_standard_option('userid', {
    description => "User ID",
    type => 'string', format => 'pve-userid',
    maxLength => 64,
});

PVE::JSONSchema::register_standard_option('realm', {
    description => "Authentication domain ID",
    type => 'string', format => 'pve-configid',
    maxLength => 32,
});

PVE::JSONSchema::register_format('pve-groupid', \&verify_groupname);
sub verify_groupname {
    my ($groupname, $noerr) = @_;

    if ($groupname !~ m/^[A-Za-z0-9\.\-_]+$/) {

	die "group name '$groupname' contains invalid characters\n" if !$noerr;

	return undef;
    }
    
    return $groupname;
}

PVE::JSONSchema::register_format('pve-roleid', \&verify_rolename);
sub verify_rolename {
    my ($rolename, $noerr) = @_;

    if ($rolename !~ m/^[A-Za-z0-9\.\-_]+$/) {

	die "role name '$rolename' contains invalid characters\n" if !$noerr;

	return undef;
    }
    
    return $rolename;
}

PVE::JSONSchema::register_format('pve-poolid', \&verify_groupname);
sub verify_poolname {
    my ($poolname, $noerr) = @_;

    if ($poolname !~ m/^[A-Za-z0-9\.\-_]+$/) {

	die "pool name '$poolname' contains invalid characters\n" if !$noerr;

	return undef;
    }
    
    return $poolname;
}

PVE::JSONSchema::register_format('pve-priv', \&verify_privname);
sub verify_privname {
    my ($priv, $noerr) = @_;

    if (!$valid_privs->{$priv}) {
	die "invalid priviledge '$priv'\n" if !$noerr;

	return undef;
    }
    
    return $priv;
}

sub userconfig_force_defaults {
    my ($cfg) = @_;

    foreach my $r (keys %$special_roles) {
	$cfg->{roles}->{$r} = $special_roles->{$r};
    }

    # fixme: remove 'root' group (not required)?

    # add root user 
    $cfg->{users}->{'root@pam'}->{enable} = 1;
}

sub parse_user_config {
    my ($filename, $raw) = @_;

    my $cfg = {};

    userconfig_force_defaults($cfg);

    while ($raw && $raw =~ s/^(.*?)(\n|$)//) {
	my $line = $1;

	next if $line =~ m/^\s*$/; # skip empty lines

	my @data;

	foreach my $d (split (/:/, $line)) {
	    $d =~ s/^\s+//; 
	    $d =~ s/\s+$//;
	    push @data, $d
	}

	my $et = shift @data;

	if ($et eq 'user') {
	    my ($user, $enable, $expire, $firstname, $lastname, $email, $comment) = @data;

	    my (undef, undef, $realm) = verify_username($user, 1);
	    if (!$realm) {
		warn "user config - ignore user '$user' - invalid user name\n";
		next;
	    }

	    $enable = $enable ? 1 : 0;

	    $expire = 0 if !$expire;

	    if ($expire !~ m/^\d+$/) {
		warn "user config - ignore user '$user' - (illegal characters in expire '$expire')\n";
		next;
	    }
	    $expire = int($expire);

	    #if (!verify_groupname ($group, 1)) {
	    #    warn "user config - ignore user '$user' - invalid characters in group name\n";
	    #    next;
	    #}

	    $cfg->{users}->{$user} = {
		enable => $enable,
		# group => $group,
	    };
	    $cfg->{users}->{$user}->{firstname} = PVE::Tools::decode_text($firstname) if $firstname;
	    $cfg->{users}->{$user}->{lastname} = PVE::Tools::decode_text($lastname) if $lastname;
	    $cfg->{users}->{$user}->{email} = $email;
	    $cfg->{users}->{$user}->{comment} = PVE::Tools::decode_text($comment) if $comment;
	    $cfg->{users}->{$user}->{expire} = $expire;

	    #$cfg->{users}->{$user}->{groups}->{$group} = 1;
	    #$cfg->{groups}->{$group}->{$user} = 1;

	} elsif ($et eq 'group') {
	    my ($group, $userlist, $comment) = @data;

	    if (!verify_groupname($group, 1)) {
		warn "user config - ignore group '$group' - invalid characters in group name\n";
		next;
	    }

	    # make sure to add the group (even if there are no members)
	    $cfg->{groups}->{$group} = { users => {} } if !$cfg->{groups}->{$group};

	    $cfg->{groups}->{$group}->{comment} = PVE::Tools::decode_text($comment) if $comment;

	    foreach my $user (split_list($userlist)) {

		if (!verify_username($user, 1)) {
		    warn "user config - ignore invalid group member '$user'\n";
		    next;
		}

		if ($cfg->{users}->{$user}) { # user exists 
		    $cfg->{users}->{$user}->{groups}->{$group} = 1;
		    $cfg->{groups}->{$group}->{users}->{$user} = 1;
		} else {
		    warn "user config - ignore invalid group member '$user'\n";
		}
	    }

	} elsif ($et eq 'role') {
	    my ($role, $privlist) = @data;
		
	    if (!verify_rolename($role, 1)) {
		warn "user config - ignore role '$role' - invalid characters in role name\n";
		next;
	    }

	    # make sure to add the role (even if there are no privileges)
	    $cfg->{roles}->{$role} = {} if !$cfg->{roles}->{$role};

	    foreach my $priv (split_list($privlist)) {
		if (defined ($valid_privs->{$priv})) {
		    $cfg->{roles}->{$role}->{$priv} = 1;
		} else {
		    warn "user config - ignore invalid priviledge '$priv'\n";
		} 
	    }
	    
	} elsif ($et eq 'acl') {
	    my ($propagate, $pathtxt, $uglist, $rolelist) = @data;

	    if (my $path = normalize_path($pathtxt)) {
		foreach my $role (split_list($rolelist)) {
			
		    if (!verify_rolename($role, 1)) {
			warn "user config - ignore invalid role name '$role' in acl\n";
			next;
		    }

		    foreach my $ug (split_list($uglist)) {
			if ($ug =~ m/^@(\w+)$/) {
			    my $group = $1;
			    if ($cfg->{groups}->{$group}) { # group exists 
				$cfg->{acl}->{$path}->{groups}->{$group}->{$role} = $propagate;
			    } else {
				warn "user config - ignore invalid acl group '$group'\n";
			    }
			} elsif (verify_username($ug, 1)) {
			    if ($cfg->{users}->{$ug}) { # user exists 
				$cfg->{acl}->{$path}->{users}->{$ug}->{$role} = $propagate;
			    } else {
				warn "user config - ignore invalid acl member '$ug'\n";
			    }
			} else {
			    warn "user config - invalid user/group '$ug' in acl\n";
			}
		    }
		}
	    } else {
		warn "user config - ignore invalid path in acl '$pathtxt'\n";
	    }
	} elsif ($et eq 'pool') {
	    my ($pool, $comment, $vmlist, $storelist) = @data;

	    if (!verify_poolname($pool, 1)) {
		warn "user config - ignore pool '$pool' - invalid characters in pool name\n";
		next;
	    }

	    # make sure to add the pool (even if there are no members)
	    $cfg->{pools}->{$pool} = { vms => {}, storage => {} } if !$cfg->{pools}->{$pool};

	    $cfg->{pools}->{$pool}->{comment} = PVE::Tools::decode_text($comment) if $comment;

	    foreach my $vmid (split_list($vmlist)) {
		if ($vmid !~ m/^\d+$/) {
		    warn "user config - ignore invalid vmid '$vmid' in pool '$pool'\n";
		    next;
		}
		$vmid = int($vmid);

		if ($cfg->{vms}->{$vmid}) {
		    warn "user config - ignore duplicate vmid '$vmid' in pool '$pool'\n";
		    next;
		}

		$cfg->{pools}->{$pool}->{vms}->{$vmid} = 1;
		    
		# record vmid ==> pool relation
		$cfg->{vms}->{$vmid} = $pool;
	    }

	    foreach my $storeid (split_list($storelist)) {
		if ($storeid !~ m/^[a-z][a-z0-9\-\_\.]*[a-z0-9]$/i) {
		    warn "user config - ignore invalid storage '$storeid' in pool '$pool'\n";
		    next;
		}
		$cfg->{pools}->{$pool}->{storage}->{$storeid} = 1;
	    }
	} else {
	    warn "user config - ignore config line: $line\n";
	}
    }

    userconfig_force_defaults($cfg);

    return $cfg;
}

sub parse_shadow_passwd {
    my ($filename, $raw) = @_;

    my $shadow = {};

    while ($raw && $raw =~ s/^(.*?)(\n|$)//) {
	my $line = $1;

	next if $line =~ m/^\s*$/; # skip empty lines

	if ($line !~ m/^\S+:\S+:$/) {
	    warn "pve shadow password: ignore invalid line $.\n";
	    next;
	}

	my ($userid, $crypt_pass) = split (/:/, $line);
	$shadow->{users}->{$userid}->{shadow} = $crypt_pass;
    }

    return $shadow;
}

sub write_domains {
    my ($filename, $cfg) = @_;

    my $data = '';

    my $wrote_default;

    foreach my $realm (sort keys %$cfg) {
	my $entry = $cfg->{$realm};
	my $type = lc($entry->{type});

	next if !$type;

	next if ($type eq 'pam') || ($type eq 'pve');

	my $formats = $valid_attributes->{$type};
	next if !$formats;

	$data .= "$type: $realm\n";

	foreach my $k (sort keys %$entry) {
	    next if $k eq 'type';
	    my $v = $entry->{$k};
	    if ($k eq 'default') {
		    $data .= "\t$k\n" if $v && !$wrote_default;
		    $wrote_default = 1;
	    } elsif (defined($formats->{$k})) {
		if (!$formats->{$k}) {
		    $data .= "\t$k\n" if $v;
		} elsif ($v =~ m/^$formats->{$k}$/) {
		    $v = PVE::Tools::encode_text($v) if $k eq 'comment';
		    $data .= "\t$k $v\n";
		} else {
		    die "invalid value '$v' for attribute '$k'\n";
		}
	    } else {
		die "invalid attribute '$k' - not supported\n";
	    }
	}

	$data .= "\n";
    }

    return $data;
}

sub parse_domains {
    my ($filename, $raw) = @_;

    my $cfg = {};

    my $default;

    while ($raw && $raw =~ s/^(.*?)(\n|$)//) {
	my $line = $1;
 
	next if $line =~ m/^\#/; # skip comment lines
	next if $line =~ m/^\s*$/; # skip empty lines

	if ($line =~ m/^(\S+):\s*(\S+)\s*$/) {
	    my $realm = $2;
	    my $type = lc($1);

	    my $ignore = 0;
	    my $entry;

	    my $formats = $valid_attributes->{$type};
	    if (!$formats) {
		$ignore = 1;
		warn "ignoring domain '$realm' - (unsupported authentication type '$type')\n";
	    } elsif (!pve_verify_realm($realm, 1)) {
		$ignore = 1;
		warn "ignoring domain '$realm' - (illegal characters)\n";
	    } else {
		$entry = { type => $type };
	    }

	    while ($raw && $raw =~ s/^(.*?)(\n|$)//) {
		$line = $1;

		next if $line =~ m/^\#/; #skip comment lines
		last if $line =~ m/^\s*$/;
		    
		next if $ignore; # skip

		if ($line =~ m/^\s+(default)\s*$/) {
		    $default = $realm if !$default;
		} elsif ($line =~ m/^\s+(\S+)(\s+(.*\S))?\s*$/) {
		    my ($k, $v) = (lc($1), $3);
		    if (defined($formats->{$k})) {
			if (!$formats->{$k} && !defined($v)) {
				$entry->{$k} = 1;			    
			} elsif ($formats->{$k} && $v =~ m/^$formats->{$k}$/) {
			    if (!defined($entry->{$k})) {
				$v = PVE::Tools::decode_text($v) if $k eq 'comment';
				$entry->{$k} = $v;
			    } else {
				warn "ignoring duplicate attribute '$k $v'\n";
			    }
			} else {
			    warn "ignoring value '$v' for attribute '$k' - invalid format\n";
			}
		    } else {
			warn "ignoring attribute '$k' - not supported\n";
		    }
		} else {
		    warn "ignore config line: $line\n";
		}
	    }

	    if ($entry->{server2} && !$entry->{server1}) {
		$entry->{server1} = $entry->{server2};
		delete $entry->{server2};
	    }

	    if ($ignore) {
		# do nothing
	    } elsif (!$entry->{server1}) {
		warn "ignoring domain '$realm' - missing server attribute\n";
	    } elsif (($entry->{type} eq "ldap") && !$entry->{user_attr}) {
		warn "ignoring domain '$realm' - missing user attribute\n";
	    } elsif (($entry->{type} eq "ldap") && !$entry->{base_dn}) {
		warn "ignoring domain '$realm' - missing base_dn attribute\n";
	    } elsif (($entry->{type} eq "ad") && !$entry->{domain}) {
		warn "ignoring domain '$realm' - missing domain attribute\n";
	    } else {
		$cfg->{$realm} = $entry;
	    }
     
	} else {
	    warn "ignore config line: $line\n";
	}
    }

    $cfg->{$default}->{default} = 1 if $default;

    # add default domains

    $cfg->{pve} = {
	type => 'builtin',
	comment => "Proxmox VE authentication server", 
    };

    $cfg->{pam} = {
	type => 'builtin',
	comment => "Linux PAM standard authentication", 
    };
	
    return $cfg;
}

sub write_shadow_config {
    my ($filename, $cfg) = @_;

    my $data = '';
    foreach my $userid (keys %{$cfg->{users}}) {
	my $crypt_pass = $cfg->{users}->{$userid}->{shadow};
	$data .= "$userid:$crypt_pass:\n";
    }

    return $data
}

sub write_user_config {
    my ($filename, $cfg) = @_;

    my $data = '';

    foreach my $user (keys %{$cfg->{users}}) {
	my $d = $cfg->{users}->{$user};
	my $firstname = $d->{firstname} ? PVE::Tools::encode_text($d->{firstname}) : '';
	my $lastname = $d->{lastname} ? PVE::Tools::encode_text($d->{lastname}) : '';
	my $email = $d->{email} || '';
	my $comment = $d->{comment} ? PVE::Tools::encode_text($d->{comment}) : '';
	my $expire = int($d->{expire} || 0);
	my $enable = $d->{enable} ? 1 : 0;
	$data .= "user:$user:$enable:$expire:$firstname:$lastname:$email:$comment:\n";
    }

    $data .= "\n";

    foreach my $group (keys %{$cfg->{groups}}) {
	my $d = $cfg->{groups}->{$group};
	my $list = join (',', keys %{$d->{users}});
	my $comment = $d->{comment} ? PVE::Tools::encode_text($d->{comment}) : '';	
	$data .= "group:$group:$list:$comment:\n";
    }

    $data .= "\n";

    foreach my $pool (keys %{$cfg->{pools}}) {
	my $d = $cfg->{pools}->{$pool};
	my $vmlist = join (',', keys %{$d->{vms}});
	my $storelist = join (',', keys %{$d->{storage}});
	my $comment = $d->{comment} ? PVE::Tools::encode_text($d->{comment}) : '';	
	$data .= "pool:$pool:$comment:$vmlist:$storelist:\n";
    }

    $data .= "\n";

    foreach my $role (keys %{$cfg->{roles}}) {
	next if $special_roles->{$role};

	my $d = $cfg->{roles}->{$role};
	my $list = join (',', keys %$d);
	$data .= "role:$role:$list:\n";
    }

    $data .= "\n";

    foreach my $path (sort keys %{$cfg->{acl}}) {
	my $d = $cfg->{acl}->{$path};

	my $ra = {};

	foreach my $group (keys %{$d->{groups}}) {
	    my $l0 = '';
	    my $l1 = '';
	    foreach my $role (sort keys %{$d->{groups}->{$group}}) {
		my $propagate = $d->{groups}->{$group}->{$role};
		if ($propagate) {
		    $l1 .= ',' if $l1;
		    $l1 .= $role;
		} else {
		    $l0 .= ',' if $l0;
		    $l0 .= $role;
		}
	    }
	    $ra->{0}->{$l0}->{"\@$group"} = 1 if $l0;
	    $ra->{1}->{$l1}->{"\@$group"} = 1 if $l1;
	}

	foreach my $user (keys %{$d->{users}}) {
	    # no need to save, because root is always 'Administartor'
	    next if $user eq 'root@pam'; 

	    my $l0 = '';
	    my $l1 = '';
	    foreach my $role (sort keys %{$d->{users}->{$user}}) {
		my $propagate = $d->{users}->{$user}->{$role};
		if ($propagate) {
		    $l1 .= ',' if $l1;
		    $l1 .= $role;
		} else {
		    $l0 .= ',' if $l0;
		    $l0 .= $role;
		}
	    }
	    $ra->{0}->{$l0}->{$user} = 1 if $l0;
	    $ra->{1}->{$l1}->{$user} = 1 if $l1;
	}

	foreach my $rolelist (sort keys %{$ra->{0}}) {
	    my $uglist = join (',', keys %{$ra->{0}->{$rolelist}});
	    $data .= "acl:0:$path:$uglist:$rolelist:\n";
	}
	foreach my $rolelist (sort keys %{$ra->{1}}) {
	    my $uglist = join (',', keys %{$ra->{1}->{$rolelist}});
	    $data .= "acl:1:$path:$uglist:$rolelist:\n";
	}
    }

    return $data;
}

sub roles {
    my ($cfg, $user, $path) = @_;

    # NOTE: we do not consider pools here. 
    # You need to use $rpcenv->roles() instead if you want that.

    return 'Administrator' if $user eq 'root@pam'; # root can do anything

    my $perm = {};

    foreach my $p (sort keys %{$cfg->{acl}}) {
	my $final = ($path eq $p);

	next if !(($p eq '/') || $final || ($path =~ m|^$p/|));

	my $acl = $cfg->{acl}->{$p};

	#print "CHECKACL $path $p\n";
	#print "ACL $path = " . Dumper ($acl);

	if (my $ri = $acl->{users}->{$user}) {
	    my $new;
	    foreach my $role (keys %$ri) {
		my $propagate = $ri->{$role};
		if ($final || $propagate) {
		    #print "APPLY ROLE $p $user $role\n";
		    $new = {} if !$new;
		    $new->{$role} = 1;
		}
	    }
	    if ($new) {
		$perm = $new; # overwrite previous settings
		next; # user privs always override group privs
	    }
	}

	my $new;
	foreach my $g (keys %{$acl->{groups}}) {
	    next if !$cfg->{groups}->{$g}->{users}->{$user};
	    if (my $ri = $acl->{groups}->{$g}) {
		foreach my $role (keys %$ri) {
		    my $propagate = $ri->{$role};
		    if ($final || $propagate) {
			#print "APPLY ROLE $p \@$g $role\n";
			$new = {} if !$new;
			$new->{$role} = 1;
		    }
		}
	    }
	}
	if ($new) {
	    $perm = $new; # overwrite previous settings
	    next;
	}
    }

    return ('NoAccess') if defined ($perm->{NoAccess});
    #return () if defined ($perm->{NoAccess});
   
    #print "permission $user $path = " . Dumper ($perm);

    my @ra = keys %$perm;

    #print "roles $user $path = " . join (',', @ra) . "\n";

    return @ra;
}
    
sub permission {
    my ($cfg, $user, $path) = @_;

    $user = verify_username($user, 1);
    return {} if !$user;

    my @ra = roles($cfg, $user, $path);
    
    my $privs = {};

    foreach my $role (@ra) {
	if (my $privset = $cfg->{roles}->{$role}) {
	    foreach my $p (keys %$privset) {
		$privs->{$p} = 1;
	    }
	}
    }

    #print "priviledges $user $path = " . Dumper ($privs);

    return $privs;
}

sub check_permissions {
    my ($username, $path, $privlist) = @_;

    $path = normalize_path($path);
    my $usercfg = cfs_read_file('user.cfg');
    my $perm = permission($usercfg, $username, $path);

    foreach my $priv (split_list($privlist)) {
	return undef if !$perm->{$priv};
    };

    return 1;
}

1;

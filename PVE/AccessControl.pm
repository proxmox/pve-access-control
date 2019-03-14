package PVE::AccessControl;

use strict;
use warnings;
use Encode;
use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;
use Net::SSLeay;
use Net::IP;
use MIME::Base64;
use Digest::SHA;
use IO::File;
use File::stat;

use PVE::OTP;
use PVE::Ticket;
use PVE::Tools qw(run_command lock_file file_get_contents split_list safe_print);
use PVE::Cluster qw(cfs_register_file cfs_read_file cfs_write_file cfs_lock_file);
use PVE::JSONSchema qw(register_standard_option get_standard_option);

use PVE::Auth::Plugin;
use PVE::Auth::AD;
use PVE::Auth::LDAP;
use PVE::Auth::PVE;
use PVE::Auth::PAM;

# load and initialize all plugins

PVE::Auth::AD->register();
PVE::Auth::LDAP->register();
PVE::Auth::PVE->register();
PVE::Auth::PAM->register();
PVE::Auth::Plugin->init();

# $authdir must be writable by root only!
my $confdir = "/etc/pve";
my $authdir = "$confdir/priv";

my $pve_www_key_fn = "$confdir/pve-www.key";

my $pve_auth_key_files = {
    priv => "$authdir/authkey.key",
    pub =>  "$confdir/authkey.pub",
    pubold => "$confdir/authkey.pub.old",
};

my $pve_auth_key_cache = {};

my $ticket_lifetime = 3600*2; # 2 hours
# TODO: set to 24h for PVE 6.0
my $authkey_lifetime = 3600*0; # rotation disabled

Crypt::OpenSSL::RSA->import_random_seed();

cfs_register_file('user.cfg',
		  \&parse_user_config,
		  \&write_user_config);

sub verify_username {
    PVE::Auth::Plugin::verify_username(@_);
}

sub pve_verify_realm {
    PVE::Auth::Plugin::pve_verify_realm(@_);
}

sub lock_user_config {
    my ($code, $errmsg) = @_;

    cfs_lock_file("user.cfg", undef, $code);
    if (my $err = $@) {
	$errmsg ? die "$errmsg: $err" : die $err;
    }
}

my $cache_read_key = sub {
    my ($type) = @_;

    my $path = $pve_auth_key_files->{$type};

    my $read_key_and_mtime = sub {
	my $fh = IO::File->new($path, "r");

	return undef if !defined($fh);

	my $st = stat($fh);
	my $pem = PVE::Tools::safe_read_from($fh, 0, 0, $path);

	close $fh;

	my $key;
	if ($type eq 'pub' || $type eq 'pubold') {
	    $key = eval { Crypt::OpenSSL::RSA->new_public_key($pem); };
	} elsif ($type eq 'priv') {
	    $key = eval { Crypt::OpenSSL::RSA->new_private_key($pem); };
	} else {
	    die "Invalid authkey type '$type'\n";
	}

	return { key => $key, mtime => $st->mtime };
    };

    if (!defined($pve_auth_key_cache->{$type})) {
	$pve_auth_key_cache->{$type} = $read_key_and_mtime->();
    } else {
	my $st = stat($path);
	if (!$st || $st->mtime != $pve_auth_key_cache->{$type}->{mtime}) {
	    $pve_auth_key_cache->{$type} = $read_key_and_mtime->();
	}
    }

    return $pve_auth_key_cache->{$type};
};

sub get_pubkey {
    my ($old) = @_;

    my $type = $old ? 'pubold' : 'pub';

    my $res = $cache_read_key->($type);
    return undef if !defined($res);

    return wantarray ? ($res->{key}, $res->{mtime}) : $res->{key};
}

sub get_privkey {
    my $res = $cache_read_key->('priv');

    if (!defined($res) || !check_authkey(1)) {
	rotate_authkey();
	$res = $cache_read_key->('priv');
    }

    return wantarray ? ($res->{key}, $res->{mtime}) : $res->{key};
}

sub check_authkey {
    my ($quiet) = @_;

    # skip check if non-quorate, as rotation is not possible anyway
    return 1 if !PVE::Cluster::check_cfs_quorum(1);

    my ($pub_key, $mtime) = get_pubkey();
    if (!$pub_key) {
	warn "auth key pair missing, generating new one..\n"  if !$quiet;
	return 0;
    } else {
	if (time() - $mtime >= $authkey_lifetime) {
	    warn "auth key pair too old, rotating..\n" if !$quiet;;
	    return 0;
	} else {
	    warn "auth key new enough, skipping rotation\n" if !$quiet;;
	    return 1;
	}
    }
}

sub rotate_authkey {
    return if $authkey_lifetime == 0;

    PVE::Cluster::cfs_lock_authkey(undef, sub {
	# re-check with lock to avoid double rotation in clusters
	return if check_authkey();

	my $old = get_pubkey();

	if ($old) {
	    eval {
		my $pem = $old->get_public_key_x509_string();
		PVE::Tools::file_set_contents($pve_auth_key_files->{pubold}, $pem);
	    };
	    die "Failed to store old auth key: $@\n" if $@;
	}

	my $new = Crypt::OpenSSL::RSA->generate_key(2048);
	eval {
	    my $pem = $new->get_public_key_x509_string();
	    PVE::Tools::file_set_contents($pve_auth_key_files->{pub}, $pem);
	};
	if ($@) {
	    if ($old) {
		warn "Failed to store new auth key - $@\n";
		warn "Reverting to previous auth key\n";
		eval {
		    my $pem = $old->get_public_key_x509_string();
		    PVE::Tools::file_set_contents($pve_auth_key_files->{pub}, $pem);
		};
		die "Failed to restore old auth key: $@\n" if $@;
	    } else {
		die "Failed to store new auth key - $@\n";
	    }
	}

	eval {
	    my $pem = $new->get_private_key_string();
	    PVE::Tools::file_set_contents($pve_auth_key_files->{priv}, $pem);
	};
	if ($@) {
	    warn "Failed to store new auth key - $@\n";
	    warn "Deleting auth key to force regeneration\n";
	    unlink $pve_auth_key_files->{pub};
	    unlink $pve_auth_key_files->{priv};
	}
    });
    die $@ if $@;
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

    my $secret =  &$get_csrfr_secret();

    return PVE::Ticket::assemble_csrf_prevention_token ($secret, $username);
}

sub verify_csrf_prevention_token {
    my ($username, $token, $noerr) = @_;

    my $secret =  &$get_csrfr_secret();

    return PVE::Ticket::verify_csrf_prevention_token(
	$secret, $username, $token, -300, $ticket_lifetime, $noerr);
}

my $get_ticket_age_range = sub {
    my ($now, $mtime, $rotated) = @_;

    my $key_age = $now - $mtime;
    $key_age = 0 if $key_age < 0;

    my $min = -300;
    my $max = $ticket_lifetime;

    if ($rotated) {
	# ticket creation after rotation is not allowed
	$min = $key_age - 300;
    } else {
	if ($key_age > $authkey_lifetime && $authkey_lifetime > 0) {
	    if (PVE::Cluster::check_cfs_quorum(1)) {
		# key should have been rotated, clamp range accordingly
		$min = $key_age - $authkey_lifetime;
	    } else {
		warn "Cluster not quorate - extending auth key lifetime!\n";
	    }
	}

	$max = $key_age + 300 if $key_age < $ticket_lifetime;
    }

    return undef if $min > $ticket_lifetime;
    return ($min, $max);
};

sub assemble_ticket {
    my ($username) = @_;

    my $rsa_priv = get_privkey();

    return PVE::Ticket::assemble_rsa_ticket($rsa_priv, 'PVE', $username);
}

sub verify_ticket {
    my ($ticket, $noerr) = @_;

    my $now = time();

    my $check = sub {
	my ($old) = @_;

	my ($rsa_pub, $rsa_mtime) = get_pubkey($old);
	return undef if !$rsa_pub;

	my ($min, $max) = $get_ticket_age_range->($now, $rsa_mtime, $old);
	return undef if !$min;

	return PVE::Ticket::verify_rsa_ticket(
	    $rsa_pub, 'PVE', $ticket, undef, $min, $max, 1);
    };

    my ($username, $age) = $check->();

    # check with old, rotated key if current key failed
    ($username, $age) = $check->(1) if !defined($username);

    if (!defined($username)) {
	if ($noerr) {
	    return undef;
	} else {
	    # raise error via undef ticket
	    PVE::Ticket::verify_rsa_ticket(undef, 'PVE');
	}
    }

    return undef if !PVE::Auth::Plugin::verify_username($username, $noerr);

    return wantarray ? ($username, $age) : $username;
}

# VNC tickets
# - they do not contain the username in plain text
# - they are restricted to a specific resource path (example: '/vms/100')
sub assemble_vnc_ticket {
    my ($username, $path) = @_;

    my $rsa_priv = get_privkey();

    $path = normalize_path($path);

    my $secret_data = "$username:$path";

    return PVE::Ticket::assemble_rsa_ticket(
	$rsa_priv, 'PVEVNC', undef, $secret_data);
}

sub verify_vnc_ticket {
    my ($ticket, $username, $path, $noerr) = @_;

    my $secret_data = "$username:$path";

    my ($rsa_pub, $rsa_mtime) = get_pubkey();
    if (!$rsa_pub || (time() - $rsa_mtime > $authkey_lifetime)) {
	if ($noerr) {
	    return undef;
	} else {
	    # raise error via undef ticket
	    PVE::Ticket::verify_rsa_ticket($rsa_pub, 'PVEVNC');
	}
    }

    return PVE::Ticket::verify_rsa_ticket(
	$rsa_pub, 'PVEVNC', $ticket, $secret_data, -20, 40, $noerr);
}

sub assemble_spice_ticket {
    my ($username, $vmid, $node) = @_;

    my $secret = &$get_csrfr_secret();

    return PVE::Ticket::assemble_spice_ticket(
	$secret, $username, $vmid, $node);
}

sub verify_spice_connect_url {
    my ($connect_str) = @_;

    my $secret = &$get_csrfr_secret();

    return PVE::Ticket::verify_spice_connect_url($secret, $connect_str);
}

sub read_x509_subject_spice {
    my ($filename) = @_;

    # read x509 subject
    my $bio = Net::SSLeay::BIO_new_file($filename, 'r');
    die "Could not open $filename using OpenSSL\n"
	if !$bio;

    my $x509 = Net::SSLeay::PEM_read_bio_X509($bio);
    Net::SSLeay::BIO_free($bio);

    die "Could not parse X509 certificate in $filename\n"
	if !$x509;

    my $nameobj = Net::SSLeay::X509_get_subject_name($x509);
    my $subject = Net::SSLeay::X509_NAME_oneline($nameobj);
    Net::SSLeay::X509_free($x509);

    # remote-viewer wants comma as seperator (not '/')
    $subject =~ s!^/!!;
    $subject =~ s!/(\w+=)!,$1!g;

    return $subject;
}

# helper to generate SPICE remote-viewer configuration
sub remote_viewer_config {
    my ($authuser, $vmid, $node, $proxy, $title, $port) = @_;

    if (!$proxy) {
	my $host = `hostname -f` || PVE::INotify::nodename();
	chomp $host;
	$proxy = $host;
    }

    my ($ticket, $proxyticket) = assemble_spice_ticket($authuser, $vmid, $node);

    my $filename = "/etc/pve/local/pve-ssl.pem";
    my $subject = read_x509_subject_spice($filename);

    my $cacert = PVE::Tools::file_get_contents("/etc/pve/pve-root-ca.pem", 8192);
    $cacert =~ s/\n/\\n/g;

    $proxy = "[$proxy]" if Net::IP::ip_is_ipv6($proxy);
    my $config = {
	'secure-attention' => "Ctrl+Alt+Ins",
	'toggle-fullscreen' => "Shift+F11",
	'release-cursor' => "Ctrl+Alt+R",
	type => 'spice',
	title => $title,
	host => $proxyticket, # this breaks tls hostname verification, so we need to use 'host-subject'
	proxy => "http://$proxy:3128",
	'tls-port' => $port,
	'host-subject' => $subject,
	ca => $cacert,
	password => $ticket,
	'delete-this-file' => 1,
    };

    return ($ticket, $proxyticket, $config);
}

sub check_user_exist {
    my ($usercfg, $username, $noerr) = @_;

    $username = PVE::Auth::Plugin::verify_username($username, $noerr);
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

    die "user '$username' is disabled\n" if !$noerr;

    return undef;
}

sub verify_one_time_pw {
    my ($usercfg, $username, $tfa_cfg, $otp) = @_;

    my $type = $tfa_cfg->{type};

    die "missing one time password for two-factor authentication '$type'\n" if !$otp;

    # fixme: proxy support?
    my $proxy;

    if ($type eq 'yubico') {
	my $keys = $usercfg->{users}->{$username}->{keys};
	PVE::OTP::yubico_verify_otp($otp, $keys, $tfa_cfg->{url},
				    $tfa_cfg->{id}, $tfa_cfg->{key}, $proxy);
    } elsif ($type eq 'oath') {
	my $keys = $usercfg->{users}->{$username}->{keys};
	PVE::OTP::oath_verify_otp($otp, $keys, $tfa_cfg->{step}, $tfa_cfg->{digits});
    } else {
	die "unknown tfa type '$type'\n";
    }
}

# password should be utf8 encoded
# Note: some plugins delay/sleep if auth fails
sub authenticate_user {
    my ($username, $password, $otp) = @_;

    die "no username specified\n" if !$username;

    my ($ruid, $realm);

    ($username, $ruid, $realm) = PVE::Auth::Plugin::verify_username($username);

    my $usercfg = cfs_read_file('user.cfg');

    check_user_enabled($usercfg, $username);

    my $ctime = time();
    my $expire = $usercfg->{users}->{$username}->{expire};

    die "account expired\n" if $expire && ($expire < $ctime);

    my $domain_cfg = cfs_read_file('domains.cfg');

    my $cfg = $domain_cfg->{ids}->{$realm};
    die "auth domain '$realm' does not exists\n" if !$cfg;
    my $plugin = PVE::Auth::Plugin->lookup($cfg->{type});
    $plugin->authenticate_user($cfg, $realm, $ruid, $password);

    if ($cfg->{tfa}) {
	my $tfa_cfg = PVE::Auth::Plugin::parse_tfa_config($cfg->{tfa});
	verify_one_time_pw($usercfg, $username, $tfa_cfg, $otp);
    }

    return $username;
}

sub domain_set_password {
    my ($realm, $username, $password) = @_;

    die "no auth domain specified" if !$realm;

    my $domain_cfg = cfs_read_file('domains.cfg');

    my $cfg = $domain_cfg->{ids}->{$realm};
    die "auth domain '$realm' does not exist\n" if !$cfg;
    my $plugin = PVE::Auth::Plugin->lookup($cfg->{type});
    $plugin->store_password($cfg, $realm, $username, $password);
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

    delete ($usercfg->{acl}->{$path})
}

# we automatically create some predefined roles by splitting privs
# into 3 groups (per category)
# root: only root is allowed to do that
# admin: an administrator can to that
# user: a normal user/customer can to that
my $privgroups = {
    VM => {
	root => [],
	admin => [
	    'VM.Config.Disk',
	    'VM.Config.CPU',
	    'VM.Config.Memory',
	    'VM.Config.Network',
	    'VM.Config.HWType',
	    'VM.Config.Options', # covers all other things
	    'VM.Allocate',
	    'VM.Clone',
	    'VM.Migrate',
	    'VM.Monitor',
	    'VM.Snapshot',
	    'VM.Snapshot.Rollback',
	],
	user => [
	    'VM.Config.CDROM', # change CDROM media
	    'VM.Console',
	    'VM.Backup',
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
    'NoAccess' => {}, # no privileges
    'Administrator' => $valid_privs, # all privileges
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

    $special_roles->{"PVETemplateUser"} = { 'VM.Clone' => 1, 'VM.Audit' => 1 };
};

create_roles();

sub create_priv_properties {
    my $properties = {};
    foreach my $priv (keys %$valid_privs) {
	$properties->{$priv} = {
	    type => 'boolean',
	    optional => 1,
	};
    }
    return $properties;
}

sub role_is_special {
    my ($role) = @_;
    return (exists $special_roles->{$role}) ? 1 : 0;
}

sub add_role_privs {
    my ($role, $usercfg, $privs) = @_;

    return if !$privs;

    die "role '$role' does not exist\n" if !$usercfg->{roles}->{$role};

    foreach my $priv (split_list($privs)) {
	if (defined ($valid_privs->{$priv})) {
	    $usercfg->{roles}->{$role}->{$priv} = 1;
	} else {
	    die "invalid privilege '$priv'\n";
	}
    }
}

sub normalize_path {
    my $path = shift;

    $path =~ s|/+|/|g;

    $path =~ s|/$||;

    $path = '/' if !$path;

    $path = "/$path" if $path !~ m|^/|;

    return undef if $path !~ m|^[[:alnum:]\.\-\_\/]+$|;

    return $path;
}

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

PVE::JSONSchema::register_format('pve-poolid', \&verify_poolname);
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
	die "invalid privilege '$priv'\n" if !$noerr;

	return undef;
    }

    return $priv;
}

sub userconfig_force_defaults {
    my ($cfg) = @_;

    foreach my $r (keys %$special_roles) {
	$cfg->{roles}->{$r} = $special_roles->{$r};
    }

    # add root user if not exists
    if (!$cfg->{users}->{'root@pam'}) {
	$cfg->{users}->{'root@pam'}->{enable} = 1;
    }
}

sub parse_user_config {
    my ($filename, $raw) = @_;

    my $cfg = {};

    userconfig_force_defaults($cfg);

    $raw = '' if !defined($raw);
    while ($raw =~ /^\s*(.+?)\s*$/gm) {
	my $line = $1;
	my @data;

	foreach my $d (split (/:/, $line)) {
	    $d =~ s/^\s+//;
	    $d =~ s/\s+$//;
	    push @data, $d
	}

	my $et = shift @data;

	if ($et eq 'user') {
	    my ($user, $enable, $expire, $firstname, $lastname, $email, $comment, $keys) = @data;

	    my (undef, undef, $realm) = PVE::Auth::Plugin::verify_username($user, 1);
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
	    # keys: allowed yubico key ids or oath secrets (base32 encoded)
	    $cfg->{users}->{$user}->{keys} = $keys if $keys;

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

		if (!PVE::Auth::Plugin::verify_username($user, 1)) {
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
			if ($ug =~ m/^@(\S+)$/) {
			    my $group = $1;
			    if ($cfg->{groups}->{$group}) { # group exists
				$cfg->{acl}->{$path}->{groups}->{$group}->{$role} = $propagate;
			    } else {
				warn "user config - ignore invalid acl group '$group'\n";
			    }
			} elsif (PVE::Auth::Plugin::verify_username($ug, 1)) {
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
	my $keys = $d->{keys} ? $d->{keys} : '';
	$data .= "user:$user:$enable:$expire:$firstname:$lastname:$email:$comment:$keys:\n";
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
	    # no need to save, because root is always 'Administrator'
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

    $user = PVE::Auth::Plugin::verify_username($user, 1);
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

sub remove_vm_access {
    my ($vmid) = @_;
    my $delVMaccessFn = sub {
        my $usercfg = cfs_read_file("user.cfg");
	my $modified;

        if (my $acl = $usercfg->{acl}->{"/vms/$vmid"}) {
            delete $usercfg->{acl}->{"/vms/$vmid"};
	    $modified = 1;
        }
        if (my $pool = $usercfg->{vms}->{$vmid}) {
            if (my $data = $usercfg->{pools}->{$pool}) {
                delete $data->{vms}->{$vmid};
                delete $usercfg->{vms}->{$vmid};
		$modified = 1;
            }
        }
	cfs_write_file("user.cfg", $usercfg) if $modified;
    };

    lock_user_config($delVMaccessFn, "access permissions cleanup for VM $vmid failed");
}

sub remove_storage_access {
    my ($storeid) = @_;

    my $deleteStorageAccessFn = sub {
        my $usercfg = cfs_read_file("user.cfg");
	my $modified;

        if (my $storage = $usercfg->{acl}->{"/storage/$storeid"}) {
            delete $usercfg->{acl}->{"/storage/$storeid"};
            $modified = 1;
        }
	foreach my $pool (keys %{$usercfg->{pools}}) {
	    delete $usercfg->{pools}->{$pool}->{storage}->{$storeid};
	    $modified = 1;
	}
        cfs_write_file("user.cfg", $usercfg) if $modified;
    };

    lock_user_config($deleteStorageAccessFn,
		     "access permissions cleanup for storage $storeid failed");
}

sub add_vm_to_pool {
    my ($vmid, $pool) = @_;

    my $addVMtoPoolFn = sub {
	my $usercfg = cfs_read_file("user.cfg");
	if (my $data = $usercfg->{pools}->{$pool}) {
	    $data->{vms}->{$vmid} = 1;
	    $usercfg->{vms}->{$vmid} = $pool;
	    cfs_write_file("user.cfg", $usercfg);
	}
    };

    lock_user_config($addVMtoPoolFn, "can't add VM $vmid to pool '$pool'");
}

sub remove_vm_from_pool {
    my ($vmid) = @_;

    my $delVMfromPoolFn = sub {
	my $usercfg = cfs_read_file("user.cfg");
	if (my $pool = $usercfg->{vms}->{$vmid}) {
	    if (my $data = $usercfg->{pools}->{$pool}) {
		delete $data->{vms}->{$vmid};
		delete $usercfg->{vms}->{$vmid};
		cfs_write_file("user.cfg", $usercfg);
	    }
	}
    };

    lock_user_config($delVMfromPoolFn, "pool cleanup for VM $vmid failed");
}

# bash completion helpers

register_standard_option('userid-completed',
    get_standard_option('userid', { completion => \&complete_username}),
);

sub complete_username {

    my $user_cfg = cfs_read_file('user.cfg');

    return [ keys %{$user_cfg->{users}} ];
}

sub complete_group {

    my $user_cfg = cfs_read_file('user.cfg');

    return [ keys %{$user_cfg->{groups}} ];
}

sub complete_realm {

    my $domain_cfg = cfs_read_file('domains.cfg');

    return [ keys %{$domain_cfg->{ids}} ];
}

1;

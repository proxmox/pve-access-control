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
use JSON;

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

my $ticket_lifetime = 3600 * 2; # 2 hours
my $auth_graceperiod = 60 * 5; # 5 minutes
my $authkey_lifetime = 3600 * 24; # rotate every 24 hours

Crypt::OpenSSL::RSA->import_random_seed();

cfs_register_file('user.cfg',
		  \&parse_user_config,
		  \&write_user_config);
cfs_register_file('priv/tfa.cfg',
		  \&parse_priv_tfa_config,
		  \&write_priv_tfa_config);

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
	my $now = time();
	if ($now - $mtime >= $authkey_lifetime) {
	    warn "auth key pair too old, rotating..\n" if !$quiet;;
	    return 0;
	} elsif ($mtime > $now + $auth_graceperiod) {
	    # a nodes RTC had a time set in the future during key generation -> ticket
	    # validity is clamped to 0+5 min grace period until now >= mtime again
	    my (undef, $old_mtime) = get_pubkey(1);
	    if ($old_mtime && $mtime >= $old_mtime && $mtime - $old_mtime < $ticket_lifetime) {
		warn "auth key pair generated in the future (key $mtime > host $now),"
		    ." but old key still exists and in valid grace period so avoid automatic"
		    ." fixup. Cluster time not in sync?\n" if !$quiet;
		return 1;
	    }
	    warn "auth key pair generated in the future (key $mtime > host $now), rotating..\n" if !$quiet;
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
	my $new = Crypt::OpenSSL::RSA->generate_key(2048);

	if ($old) {
	    eval {
		my $pem = $old->get_public_key_x509_string();
		# mtime is used for caching and ticket age range calculation
		PVE::Tools::file_set_contents($pve_auth_key_files->{pubold}, $pem);
	    };
	    die "Failed to store old auth key: $@\n" if $@;
	}

	eval {
	    my $pem = $new->get_public_key_x509_string();
	    # mtime is used for caching and ticket age range calculation,
	    # should be close to that of pubold above
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

PVE::JSONSchema::register_standard_option('tokenid', {
    description => "API token identifier.",
    type => "string",
    format => "pve-tokenid",
});

our $token_subid_regex = $PVE::Auth::Plugin::realm_regex;

# username@realm username realm tokenid
our $token_full_regex = qr/((${PVE::Auth::Plugin::user_regex})\@(${PVE::Auth::Plugin::realm_regex}))!(${token_subid_regex})/;

our $userid_or_token_regex = qr/^$PVE::Auth::Plugin::user_regex\@$PVE::Auth::Plugin::realm_regex(?:!$token_subid_regex)?$/;

sub split_tokenid {
    my ($tokenid, $noerr) = @_;

    if ($tokenid =~ /^${token_full_regex}$/) {
	return ($1, $4);
    }

    die "'$tokenid' is not a valid token ID - not able to split into user and token parts\n" if !$noerr;

    return undef;
}

sub join_tokenid {
    my ($username, $tokensubid) = @_;

    my $joined = "${username}!${tokensubid}";

    return pve_verify_tokenid($joined);
}

PVE::JSONSchema::register_format('pve-tokenid', \&pve_verify_tokenid);
sub pve_verify_tokenid {
    my ($tokenid, $noerr) = @_;

    if ($tokenid =~ /^${token_full_regex}$/) {
	return wantarray ? ($tokenid, $2, $3, $4) : $tokenid;
    }

    die "value '$tokenid' does not look like a valid token ID\n" if !$noerr;

    return undef;
}


my $csrf_prevention_secret;
my $csrf_prevention_secret_legacy;
my $get_csrfr_secret = sub {
    if (!$csrf_prevention_secret) {
	my $input = PVE::Tools::file_get_contents($pve_www_key_fn);
	$csrf_prevention_secret = Digest::SHA::hmac_sha256_base64($input);
	$csrf_prevention_secret_legacy = Digest::SHA::sha1_base64($input);
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

    my $secret = $get_csrfr_secret->();

    # FIXME: remove with PVE 7 and/or refactor all into PVE::Ticket ?
    if ($token =~ m/^([A-Z0-9]{8}):(\S+)$/) {
	my $sig = $2;
	if (length($sig) == 27) {
	    # the legacy secret got populated by above get_csrfr_secret call
	    $secret = $csrf_prevention_secret_legacy;
	}
    }

    return PVE::Ticket::verify_csrf_prevention_token(
	$secret, $username, $token, -$auth_graceperiod, $ticket_lifetime, $noerr);
}

my $get_ticket_age_range = sub {
    my ($now, $mtime, $rotated) = @_;

    my $key_age = $now - $mtime;
    $key_age = 0 if $key_age < 0;

    my $min = -$auth_graceperiod;
    my $max = $ticket_lifetime;

    if ($rotated) {
	# ticket creation after rotation is not allowed
	$min = $key_age - $auth_graceperiod;
    } else {
	if ($key_age > $authkey_lifetime && $authkey_lifetime > 0) {
	    if (PVE::Cluster::check_cfs_quorum(1)) {
		# key should have been rotated, clamp range accordingly
		$min = $key_age - $authkey_lifetime;
	    } else {
		warn "Cluster not quorate - extending auth key lifetime!\n";
	    }
	}

	$max = $key_age + $auth_graceperiod if $key_age < $ticket_lifetime;
    }

    return undef if $min > $ticket_lifetime;
    return ($min, $max);
};

sub assemble_ticket {
    my ($data) = @_;

    my $rsa_priv = get_privkey();

    return PVE::Ticket::assemble_rsa_ticket($rsa_priv, 'PVE', $data);
}

sub verify_ticket {
    my ($ticket, $noerr) = @_;

    my $now = time();

    my $check = sub {
	my ($old) = @_;

	my ($rsa_pub, $rsa_mtime) = get_pubkey($old);
	return undef if !$rsa_pub;

	my ($min, $max) = $get_ticket_age_range->($now, $rsa_mtime, $old);
	return undef if !defined($min);

	return PVE::Ticket::verify_rsa_ticket(
	    $rsa_pub, 'PVE', $ticket, undef, $min, $max, 1);
    };

    my ($data, $age) = $check->();

    # check with old, rotated key if current key failed
    ($data, $age) = $check->(1) if !defined($data);

    my $auth_failure = sub {
	if ($noerr) {
	    return undef;
	} else {
	    # raise error via undef ticket
	    PVE::Ticket::verify_rsa_ticket(undef, 'PVE');
	}
    };

    if (!defined($data)) {
	return $auth_failure->();
    }

    my ($username, $tfa_info);
    if ($data =~ m{^u2f!([^!]+)!([0-9a-zA-Z/.=_\-+]+)$}) {
	# Ticket for u2f-users:
	($username, my $challenge) = ($1, $2);
	if ($challenge eq 'verified') {
	    # u2f challenge was completed
	    $challenge = undef;
	} elsif (!wantarray) {
	    # The caller is not aware there could be an ongoing challenge,
	    # so we treat this ticket as invalid:
	    return $auth_failure->();
	}
	$tfa_info = {
	    type => 'u2f',
	    challenge => $challenge,
	};
    } elsif ($data =~ /^tfa!(.*)$/) {
	# TOTP and Yubico don't require a challenge so this is the generic
	# 'missing 2nd factor ticket'
	$username = $1;
	$tfa_info = { type => 'tfa' };
    } else {
	# Regular ticket (full access)
	$username = $data;
    }

    return undef if !PVE::Auth::Plugin::verify_username($username, $noerr);

    return wantarray ? ($username, $age, $tfa_info) : $username;
}

sub verify_token {
    my ($api_token) = @_;

    die "no API token specified\n" if !$api_token;

    my ($tokenid, $value);
    if ($api_token =~ /^(.*)=(.*)$/) {
	$tokenid = $1;
	$value = $2;
    } else {
	die "no tokenid specified\n";
    }

    my ($username, $token) = split_tokenid($tokenid);

    my $usercfg = cfs_read_file('user.cfg');
    check_user_enabled($usercfg, $username);
    check_token_exist($usercfg, $username, $token);

    my $ctime = time();

    my $user = $usercfg->{users}->{$username};
    die "account expired\n" if $user->{expire} && ($user->{expire} < $ctime);

    my $token_info = $user->{tokens}->{$token};
    die "token expired\n" if $token_info->{expire} && ($token_info->{expire} < $ctime);

    die "invalid token value!\n" if !PVE::Cluster::verify_token($tokenid, $value);

    return wantarray ? ($tokenid) : $tokenid;
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
    if (!$rsa_pub || (time() - $rsa_mtime > $authkey_lifetime && $authkey_lifetime > 0)) {
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

sub check_token_exist {
    my ($usercfg, $username, $tokenid, $noerr) = @_;

    my $user = check_user_exist($usercfg, $username, $noerr);
    return undef if !$user;

    return $user->{tokens}->{$tokenid}
	if defined($user->{tokens}) && $user->{tokens}->{$tokenid};

    die "no such token '$tokenid' for user '$username'\n" if !$noerr;

    return undef;
}

sub verify_one_time_pw {
    my ($type, $username, $keys, $tfa_cfg, $otp) = @_;

    die "missing one time password for two-factor authentication '$type'\n" if !$otp;

    # fixme: proxy support?
    my $proxy;

    if ($type eq 'yubico') {
	PVE::OTP::yubico_verify_otp($otp, $keys, $tfa_cfg->{url},
				    $tfa_cfg->{id}, $tfa_cfg->{key}, $proxy);
    } elsif ($type eq 'oath') {
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
    die "auth domain '$realm' does not exist\n" if !$cfg;
    my $plugin = PVE::Auth::Plugin->lookup($cfg->{type});
    $plugin->authenticate_user($cfg, $realm, $ruid, $password);

    my ($type, $tfa_data) = user_get_tfa($username, $realm);
    if ($type) {
	if ($type eq 'u2f') {
	    # Note that if the user did not manage to complete the initial u2f registration
	    # challenge we have a hash containing a 'challenge' entry in the user's tfa.cfg entry:
	    $tfa_data = undef if exists $tfa_data->{challenge};
	} elsif (!defined($otp)) {
	    # The user requires a 2nd factor but has not provided one. Return success but
	    # don't clear $tfa_data.
	} else {
	    my $keys = $tfa_data->{keys};
	    my $tfa_cfg = $tfa_data->{config};
	    verify_one_time_pw($type, $username, $keys, $tfa_cfg, $otp);
	    $tfa_data = undef;
	}

	# Return the type along with the rest:
	if ($tfa_data) {
	    $tfa_data = {
		type => $type,
		data => $tfa_data,
	    };
	}
    }

    return wantarray ? ($username, $tfa_data) : $username;
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
	    'VM.Config.Cloudinit',
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
    SDN => {
	root => [],
	admin => [
	    'SDN.Allocate',
	    'SDN.Audit',
	],
	audit => [
	    'SDN.Audit',
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

sub lookup_username {
    my ($username, $noerr) = @_;

    $username =~ m!^(${PVE::Auth::Plugin::user_regex})\@(${PVE::Auth::Plugin::realm_regex})$!;

    my $realm = $2;
    my $domain_cfg = cfs_read_file("domains.cfg");
    my $casesensitive = $domain_cfg->{ids}->{$realm}->{'case-sensitive'} // 1;
    my $usercfg = cfs_read_file('user.cfg');

    if (!$casesensitive) {
	my @matches = grep { lc $username eq lc $_ } (keys %{$usercfg->{users}});

	die "ambiguous case insensitive match of username '$username', cannot safely grant access!\n"
	    if scalar @matches > 1 && !$noerr;

	return $matches[0]
    }

    return $username;
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

sub check_path {
    my ($path) = @_;
    return $path =~ m!^(
	/
	|/access
	|/access/groups
	|/access/realm
	|/nodes
	|/nodes/[[:alnum:]\.\-\_]+
	|/pool
	|/pool/[[:alnum:]\.\-\_]+
	|/sdn
	|/storage
	|/storage/[[:alnum:]\.\-\_]+
	|/vms
	|/vms/[1-9][0-9]{2,}
    )$!xs;
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
		} else {
		    warn "user config - ignore invalid group member '$user'\n";
		}
		$cfg->{groups}->{$group}->{users}->{$user} = 1;
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
		    warn "user config - ignore invalid privilege '$priv'\n";
		}
	    }

	} elsif ($et eq 'acl') {
	    my ($propagate, $pathtxt, $uglist, $rolelist) = @data;

	    $propagate = $propagate ? 1 : 0;

	    if (my $path = normalize_path($pathtxt)) {
		foreach my $role (split_list($rolelist)) {

		    if (!verify_rolename($role, 1)) {
			warn "user config - ignore invalid role name '$role' in acl\n";
			next;
		    }

		    if (!$cfg->{roles}->{$role}) {
			warn "user config - ignore invalid acl role '$role'\n";
			next;
		    }

		    foreach my $ug (split_list($uglist)) {
			my ($group) = $ug =~ m/^@(\S+)$/;

			if ($group && verify_groupname($group, 1)) {
			    if (!$cfg->{groups}->{$group}) { # group does not exist
				warn "user config - ignore invalid acl group '$group'\n";
			    }
			    $cfg->{acl}->{$path}->{groups}->{$group}->{$role} = $propagate;
			} elsif (PVE::Auth::Plugin::verify_username($ug, 1)) {
			    if (!$cfg->{users}->{$ug}) { # user does not exist
				warn "user config - ignore invalid acl member '$ug'\n";
			    }
			    $cfg->{acl}->{$path}->{users}->{$ug}->{$role} = $propagate;
			} elsif (my ($user, $token) = split_tokenid($ug, 1)) {
			    if (check_token_exist($cfg, $user, $token, 1)) {
				$cfg->{acl}->{$path}->{tokens}->{$ug}->{$role} = $propagate;
			    } else {
				warn "user config - ignore invalid acl token '$ug'\n";
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
	} elsif ($et eq 'token') {
	    my ($tokenid, $expire, $privsep, $comment) = @data;

	    my ($user, $token) = split_tokenid($tokenid, 1);
	    if (!($user && $token)) {
		warn "user config - ignore invalid tokenid '$tokenid'\n";
		next;
	    }

	    $privsep = $privsep ? 1 : 0;

	    $expire = 0 if !$expire;

	    if ($expire !~ m/^\d+$/) {
		warn "user config - ignore token '$tokenid' - (illegal characters in expire '$expire')\n";
		next;
	    }
	    $expire = int($expire);

	    if (my $user_cfg = $cfg->{users}->{$user}) { # user exists
		$user_cfg->{tokens}->{$token} = {} if !$user_cfg->{tokens}->{$token};
		my $token_cfg = $user_cfg->{tokens}->{$token};
		$token_cfg->{privsep} = $privsep;
		$token_cfg->{expire} = $expire;
		$token_cfg->{comment} = PVE::Tools::decode_text($comment) if $comment;
	    } else {
		warn "user config - ignore token '$tokenid' - user does not exist\n";
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

    foreach my $user (sort keys %{$cfg->{users}}) {
	my $d = $cfg->{users}->{$user};
	my $firstname = $d->{firstname} ? PVE::Tools::encode_text($d->{firstname}) : '';
	my $lastname = $d->{lastname} ? PVE::Tools::encode_text($d->{lastname}) : '';
	my $email = $d->{email} || '';
	my $comment = $d->{comment} ? PVE::Tools::encode_text($d->{comment}) : '';
	my $expire = int($d->{expire} || 0);
	my $enable = $d->{enable} ? 1 : 0;
	my $keys = $d->{keys} ? $d->{keys} : '';
	$data .= "user:$user:$enable:$expire:$firstname:$lastname:$email:$comment:$keys:\n";

	my $user_tokens = $d->{tokens};
	foreach my $token (sort keys %$user_tokens) {
	    my $td = $user_tokens->{$token};
	    my $full_tokenid = join_tokenid($user, $token);
	    my $comment = $td->{comment} ? PVE::Tools::encode_text($td->{comment}) : '';
	    my $expire = int($td->{expire} || 0);
	    my $privsep = $td->{privsep} ? 1 : 0;
	    $data .= "token:$full_tokenid:$expire:$privsep:$comment:\n";
	}
    }

    $data .= "\n";

    foreach my $group (sort keys %{$cfg->{groups}}) {
	my $d = $cfg->{groups}->{$group};
	my $list = join (',', sort keys %{$d->{users}});
	my $comment = $d->{comment} ? PVE::Tools::encode_text($d->{comment}) : '';
	$data .= "group:$group:$list:$comment:\n";
    }

    $data .= "\n";

    foreach my $pool (sort keys %{$cfg->{pools}}) {
	my $d = $cfg->{pools}->{$pool};
	my $vmlist = join (',', sort keys %{$d->{vms}});
	my $storelist = join (',', sort keys %{$d->{storage}});
	my $comment = $d->{comment} ? PVE::Tools::encode_text($d->{comment}) : '';
	$data .= "pool:$pool:$comment:$vmlist:$storelist:\n";
    }

    $data .= "\n";

    foreach my $role (sort keys %{$cfg->{roles}}) {
	next if $special_roles->{$role};

	my $d = $cfg->{roles}->{$role};
	my $list = join (',', sort keys %$d);
	$data .= "role:$role:$list:\n";
    }

    $data .= "\n";

    my $collect_rolelist_members = sub {
	my ($acl_members, $result, $prefix, $exclude) = @_;

	foreach my $member (keys %$acl_members) {
	    next if $exclude && $member eq $exclude;

	    my $l0 = '';
	    my $l1 = '';
	    foreach my $role (sort keys %{$acl_members->{$member}}) {
		my $propagate = $acl_members->{$member}->{$role};
		if ($propagate) {
		    $l1 .= ',' if $l1;
		    $l1 .= $role;
		} else {
		    $l0 .= ',' if $l0;
		    $l0 .= $role;
		}
	    }
	    $result->{0}->{$l0}->{"${prefix}${member}"} = 1 if $l0;
	    $result->{1}->{$l1}->{"${prefix}${member}"} = 1 if $l1;
	}
    };

    foreach my $path (sort keys %{$cfg->{acl}}) {
	my $d = $cfg->{acl}->{$path};

	my $rolelist_members = {};

	$collect_rolelist_members->($d->{'groups'}, $rolelist_members, '@');

	# no need to save 'root@pam', it is always 'Administrator'
	$collect_rolelist_members->($d->{'users'}, $rolelist_members, '', 'root@pam');

	$collect_rolelist_members->($d->{'tokens'}, $rolelist_members, '');

	foreach my $propagate (0,1) {
	    my $filtered = $rolelist_members->{$propagate};
	    foreach my $rolelist (sort keys %$filtered) {
		my $uglist = join (',', sort keys %{$filtered->{$rolelist}});
		$data .= "acl:$propagate:$path:$uglist:$rolelist:\n";
	    }

	}
    }

    return $data;
}

# The TFA configuration in priv/tfa.cfg format contains one line per user of
# the form:
#     USER:TYPE:DATA
# DATA is a base64 encoded json string and its format depends on the type.
sub parse_priv_tfa_config {
    my ($filename, $raw) = @_;

    my $users = {};
    my $cfg = { users => $users };

    $raw = '' if !defined($raw);
    while ($raw =~ /^\s*(.+?)\s*$/gm) {
	my $line = $1;
	my ($user, $type, $data) = split(/:/, $line, 3);

	my (undef, undef, $realm) = PVE::Auth::Plugin::verify_username($user, 1);
	if (!$realm) {
	    warn "user tfa config - ignore user '$user' - invalid user name\n";
	    next;
	}

	$data = decode_json(decode_base64($data));

	$users->{$user} = {
	    type => $type,
	    data => $data,
	};
    }

    return $cfg;
}

sub write_priv_tfa_config {
    my ($filename, $cfg) = @_;

    my $output = '';

    my $users = $cfg->{users};
    foreach my $user (sort keys %$users) {
	my $info = $users->{$user};
	next if !%$info; # skip empty entries

	$info = {%$info}; # copy to verify contents:

	my $type = delete $info->{type};
	my $data = delete $info->{data};

	if (my @keys = keys %$info) {
	    die "invalid keys in TFA config for user $user: " . join(', ', @keys) . "\n";
	}

	$data = encode_base64(encode_json($data), '');
	$output .= "${user}:${type}:${data}\n";
    }

    return $output;
}

sub roles {
    my ($cfg, $user, $path) = @_;

    # NOTE: we do not consider pools here.
    # NOTE: for privsep tokens, this does not filter roles by those that the
    # corresponding user has.
    # Use $rpcenv->permission() for any actual permission checks!

    return 'Administrator' if $user eq 'root@pam'; # root can do anything

    if (pve_verify_tokenid($user, 1)) {
	my $tokenid = $user;
	my ($username, $token) = split_tokenid($tokenid);

	my $token_info = $cfg->{users}->{$username}->{tokens}->{$token};
	return () if !$token_info;

	my $user_roles = roles($cfg, $username, $path);

	# return full user privileges
	return $user_roles if !$token_info->{privsep};
    }

    my $roles = {};

    foreach my $p (sort keys %{$cfg->{acl}}) {
	my $final = ($path eq $p);

	next if !(($p eq '/') || $final || ($path =~ m|^$p/|));

	my $acl = $cfg->{acl}->{$p};

	#print "CHECKACL $path $p\n";
	#print "ACL $path = " . Dumper ($acl);
	if (my $ri = $acl->{tokens}->{$user}) {
	    my $new;
	    foreach my $role (keys %$ri) {
		my $propagate = $ri->{$role};
		if ($final || $propagate) {
		    #print "APPLY ROLE $p $user $role\n";
		    $new = {} if !$new;
		    $new->{$role} = $propagate;
		}
	    }
	    if ($new) {
		$roles = $new; # overwrite previous settings
		next;
	    }
	}

	if (my $ri = $acl->{users}->{$user}) {
	    my $new;
	    foreach my $role (keys %$ri) {
		my $propagate = $ri->{$role};
		if ($final || $propagate) {
		    #print "APPLY ROLE $p $user $role\n";
		    $new = {} if !$new;
		    $new->{$role} = $propagate;
		}
	    }
	    if ($new) {
		$roles = $new; # overwrite previous settings
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
			$new->{$role} = $propagate;
		    }
		}
	    }
	}
	if ($new) {
	    $roles = $new; # overwrite previous settings
	    next;
	}
    }

    return { 'NoAccess' => $roles->{NoAccess} } if defined ($roles->{NoAccess});
    #return () if defined ($roles->{NoAccess});

    #print "permission $user $path = " . Dumper ($roles);

    #print "roles $user $path = " . join (',', @ra) . "\n";

    return $roles;
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

my $USER_CONTROLLED_TFA_TYPES = {
    u2f => 1,
    oath => 1,
};

# Delete an entry by setting $data=undef in which case $type is ignored.
# Otherwise both must be valid.
sub user_set_tfa {
    my ($userid, $realm, $type, $data, $cached_usercfg, $cached_domaincfg) = @_;

    if (defined($data) && !defined($type)) {
	# This is an internal usage error and should not happen
	die "cannot set tfa data without a type\n";
    }

    my $user_cfg = $cached_usercfg || cfs_read_file('user.cfg');
    my $user = $user_cfg->{users}->{$userid}
	or die "user '$userid' not found\n";

    my $domain_cfg = $cached_domaincfg || cfs_read_file('domains.cfg');
    my $realm_cfg = $domain_cfg->{ids}->{$realm};
    die "auth domain '$realm' does not exist\n" if !$realm_cfg;

    my $realm_tfa = $realm_cfg->{tfa};
    if (defined($realm_tfa)) {
	$realm_tfa = PVE::Auth::Plugin::parse_tfa_config($realm_tfa);
	# If the realm has a TFA setting, we're only allowed to use that.
	if (defined($data)) {
	    my $required_type = $realm_tfa->{type};
	    if ($required_type ne $type) {
		die "realm '$realm' only allows TFA of type '$required_type\n";
	    }

	    if (defined($data->{config})) {
		# XXX: Is it enough if the type matches? Or should the configuration also match?
	    }

	    # realm-configured tfa always uses a simple key list, so use the user.cfg
	    $user->{keys} = $data->{keys};
	} else {
	    die "realm '$realm' does not allow removing the 2nd factor\n";
	}
    } else {
	# Without a realm-enforced TFA setting the user can add a u2f or totp entry by themselves.
	# The 'yubico' type requires yubico server settings, which have to be configured on the
	# realm, so this is not supported here:
	die "domain '$realm' does not support TFA type '$type'\n"
	    if defined($data) && !$USER_CONTROLLED_TFA_TYPES->{$type};
    }

    # Custom TFA entries are stored in priv/tfa.cfg as they can be more complet: u2f uses a
    # public key and a key handle, TOTP requires the usual totp settings...

    my $tfa_cfg = cfs_read_file('priv/tfa.cfg');
    my $tfa = ($tfa_cfg->{users}->{$userid} //= {});

    if (defined($data)) {
	$tfa->{type} = $type;
	$tfa->{data} = $data;
	cfs_write_file('priv/tfa.cfg', $tfa_cfg);

	$user->{keys} = "x!$type";
    } else {
	delete $tfa_cfg->{users}->{$userid};
	cfs_write_file('priv/tfa.cfg', $tfa_cfg);

	delete $user->{keys};
    }

    cfs_write_file('user.cfg', $user_cfg);
}

sub user_get_tfa {
    my ($username, $realm) = @_;

    my $user_cfg = cfs_read_file('user.cfg');
    my $user = $user_cfg->{users}->{$username}
	or die "user '$username' not found\n";

    my $keys = $user->{keys};

    my $domain_cfg = cfs_read_file('domains.cfg');
    my $realm_cfg = $domain_cfg->{ids}->{$realm};
    die "auth domain '$realm' does not exist\n" if !$realm_cfg;

    my $realm_tfa = $realm_cfg->{tfa};
    $realm_tfa = PVE::Auth::Plugin::parse_tfa_config($realm_tfa)
	if $realm_tfa;

    if (!$keys) {
	return if !$realm_tfa;
	die "missing required 2nd keys\n";
    }

    # new style config starts with an 'x' and optionally contains a !<type> suffix
    if ($keys !~ /^x(?:!.*)?$/) {
	# old style config, find the type via the realm
	return if !$realm_tfa;
	return ($realm_tfa->{type}, {
	    keys => $keys,
	    config => $realm_tfa,
	});
    } else {
	my $tfa_cfg = cfs_read_file('priv/tfa.cfg');
	my $tfa = $tfa_cfg->{users}->{$username};
	return if !$tfa; # should not happen (user.cfg wasn't cleaned up?)

	if ($realm_tfa) {
	    # if the realm has a tfa setting we need to verify the type:
	    die "auth domain '$realm' and user have mismatching TFA settings\n"
		if $realm_tfa && $realm_tfa->{type} ne $tfa->{type};
	}

	return ($tfa->{type}, $tfa->{data});
    }
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

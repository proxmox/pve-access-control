package PVE::AccessControl;

use strict;
use warnings;
use Encode;
use Crypt::OpenSSL::Random;
use Crypt::OpenSSL::RSA;
use Net::SSLeay;
use Net::IP;
use MIME::Base32;
use MIME::Base64;
use Digest::SHA;
use IO::File;
use File::stat;
use JSON;
use Scalar::Util 'weaken';
use URI::Escape;

use PVE::Exception qw(raise_perm_exc raise_param_exc);
use PVE::OTP;
use PVE::Ticket;
use PVE::Tools qw(run_command lock_file file_get_contents split_list safe_print);
use PVE::Cluster qw(cfs_register_file cfs_read_file cfs_write_file cfs_lock_file);
use PVE::JSONSchema qw(register_standard_option get_standard_option);

use PVE::RS::TFA;

use PVE::Auth::Plugin;
use PVE::Auth::AD;
use PVE::Auth::LDAP;
use PVE::Auth::PVE;
use PVE::Auth::PAM;
use PVE::Auth::OpenId;

# load and initialize all plugins

PVE::Auth::AD->register();
PVE::Auth::LDAP->register();
PVE::Auth::PVE->register();
PVE::Auth::PAM->register();
PVE::Auth::OpenId->register();
PVE::Auth::Plugin->init();

# $authdir must be writable by root only!
my $confdir = "/etc/pve";
my $authdir = "$confdir/priv";

my $pve_www_key_fn = "$confdir/pve-www.key";

my $pve_auth_key_files = {
    priv => "$authdir/authkey.key",
    pub => "$confdir/authkey.pub",
    pubold => "$confdir/authkey.pub.old",
};

my $pve_auth_key_cache = {};

my $ticket_lifetime = 3600 * 2; # 2 hours
my $auth_graceperiod = 60 * 5; # 5 minutes
my $authkey_lifetime = 3600 * 24; # rotate every 24 hours

Crypt::OpenSSL::RSA->import_random_seed();

cfs_register_file('user.cfg', \&parse_user_config, \&write_user_config);
cfs_register_file('priv/tfa.cfg', \&parse_priv_tfa_config, \&write_priv_tfa_config);

sub verify_username {
    PVE::Auth::Plugin::verify_username(@_);
}

sub pve_verify_realm {
    PVE::Auth::Plugin::pve_verify_realm(@_);
}

# Locking both config files together is only ever allowed in one order:
#  1) tfa config
#  2) user config
# If we permit the other way round, too, we might end up deadlocking!
my $user_config_locked;

sub lock_user_config {
    my ($code, $errmsg) = @_;

    my $locked = 1;
    $user_config_locked = \$locked;
    weaken $user_config_locked; # make this scope guard signal safe...

    cfs_lock_file("user.cfg", undef, $code);
    $user_config_locked = undef;
    if (my $err = $@) {
        $errmsg ? die "$errmsg: $err" : die $err;
    }
}

sub lock_tfa_config {
    my ($code, $errmsg) = @_;

    die "tfa config lock cannot be acquired while holding user config lock\n"
        if ($user_config_locked && $$user_config_locked);

    my $res = cfs_lock_file("priv/tfa.cfg", undef, $code);
    if (my $err = $@) {
        $errmsg ? die "$errmsg: $err" : die $err;
    }

    return $res;
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
        warn "auth key pair missing, generating new one..\n" if !$quiet;
        return 0;
    } else {
        my $now = time();
        if ($now - $mtime >= $authkey_lifetime) {
            warn "auth key pair too old, rotating..\n" if !$quiet;
            return 0;
        } elsif ($mtime > $now + $auth_graceperiod) {
            # a nodes RTC had a time set in the future during key generation -> ticket
            # validity is clamped to 0+5 min grace period until now >= mtime again
            my (undef, $old_mtime) = get_pubkey(1);
            if ($old_mtime && $mtime >= $old_mtime && $mtime - $old_mtime < $ticket_lifetime) {
                warn "auth key pair generated in the future (key $mtime > host $now),"
                    . " but old key still exists and in valid grace period so avoid automatic"
                    . " fixup. Cluster time not in sync?\n"
                    if !$quiet;
                return 1;
            }
            warn "auth key pair generated in the future (key $mtime > host $now), rotating..\n"
                if !$quiet;
            return 0;
        } else {
            warn "auth key new enough, skipping rotation\n" if !$quiet;
            return 1;
        }
    }
}

sub rotate_authkey {
    return if $authkey_lifetime == 0;

    PVE::Cluster::cfs_lock_authkey(
        undef,
        sub {
            # stat() calls might be answered from the kernel page cache for up to
            # 1s, so this special dance is needed to avoid a double rotation in
            # clusters *despite* the cfs_lock context..

            # drop in-process cache hash
            $pve_auth_key_cache = {};
            # force open/close of file to invalidate page cache entry
            get_pubkey();
            # now re-check with lock held and page cache invalidated so that stat()
            # does the right thing, and any key updates by other nodes are visible.
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
        },
    );
    die $@ if $@;
}

PVE::JSONSchema::register_standard_option(
    'tokenid',
    {
        description => "API token identifier.",
        type => "string",
        format => "pve-tokenid",
    },
);

our $token_subid_regex = $PVE::Auth::Plugin::realm_regex;

# username@realm username realm tokenid
our $token_full_regex =
    qr/((${PVE::Auth::Plugin::user_regex})\@(${PVE::Auth::Plugin::realm_regex}))!(${token_subid_regex})/;

our $userid_or_token_regex =
    qr/^$PVE::Auth::Plugin::user_regex\@$PVE::Auth::Plugin::realm_regex(?:!$token_subid_regex)?\z/;

sub split_tokenid {
    my ($tokenid, $noerr) = @_;

    if ($tokenid =~ /^${token_full_regex}\z/) {
        return ($1, $4);
    }

    die "'$tokenid' is not a valid token ID - not able to split into user and token parts\n"
        if !$noerr;

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

    if ($tokenid =~ /^${token_full_regex}\z/) {
        return wantarray ? ($tokenid, $2, $3, $4) : $tokenid;
    }

    die "value '$tokenid' does not look like a valid token ID\n" if !$noerr;

    return undef;
}

my $csrf_prevention_secret;
my $get_csrfr_secret = sub {
    if (!$csrf_prevention_secret) {
        my $input = PVE::Tools::file_get_contents($pve_www_key_fn);
        $csrf_prevention_secret = Digest::SHA::hmac_sha256_base64($input);
    }
    return $csrf_prevention_secret;
};

sub assemble_csrf_prevention_token {
    my ($username) = @_;

    my $secret = &$get_csrfr_secret();

    return PVE::Ticket::assemble_csrf_prevention_token($secret, $username);
}

sub verify_csrf_prevention_token {
    my ($username, $token, $noerr) = @_;

    my $secret = $get_csrfr_secret->();

    return PVE::Ticket::verify_csrf_prevention_token(
        $secret, $username, $token, -$auth_graceperiod, $ticket_lifetime, $noerr,
    );
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

sub assemble_ticket : prototype($;$) {
    my ($data, $aad) = @_;

    my $rsa_priv = get_privkey();

    return PVE::Ticket::assemble_rsa_ticket($rsa_priv, 'PVE', $data, $aad);
}

# Returns the username, "age" and tfa info.
#
# Note that for the new-style outh, tfa info is never set, as it only uses the `/ticket` api call
# via the new 'tfa-challenge' parameter, so this part can go with PVE-8.
#
# New-style auth still uses this function, but sets `$tfa_ticket` to true when validating the tfa
# ticket.
sub verify_ticket : prototype($;$$) {
    my ($ticket, $noerr, $tfa_ticket_aad) = @_;

    my $now = time();

    my $check = sub {
        my ($old) = @_;

        my ($rsa_pub, $rsa_mtime) = get_pubkey($old);
        return undef if !$rsa_pub;

        my ($min, $max) = $get_ticket_age_range->($now, $rsa_mtime, $old);
        return undef if !defined($min);

        return PVE::Ticket::verify_rsa_ticket($rsa_pub, 'PVE', $ticket, $tfa_ticket_aad, $min,
            $max, 1);
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

    if ($tfa_ticket_aad) {
        # We're validating a ticket-call's 'tfa-challenge' parameter, so just return its data.
        if ($data =~ /^!tfa!(.*)\z/) {
            return $1;
        }
        die "bad ticket\n";
    }

    my ($username, $tfa_info);
    if ($data =~ /^!tfa!(.*)\z/) {
        # PBS style half-authenticated ticket, contains a json string form of a `TfaChallenge`
        # object.
        # This type of ticket does not contain the user name.
        return { type => 'new', data => $1 };
    }
    if ($data =~ m{^u2f!([^!]+)!([0-9a-zA-Z/.=_\-+]+)\z}) {
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
    } elsif ($data =~ /^tfa!(.*)\z/) {
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
    if ($api_token =~ /^(.*)=(.*)\z/) {
        $tokenid = $1;
        $value = $2;
    } else {
        die "no tokenid specified\n";
    }

    my ($username, $token) = split_tokenid($tokenid);

    my $usercfg = cfs_read_file('user.cfg');
    check_user_enabled($usercfg, $username);
    check_token_exist($usercfg, $username, $token);

    my $user = $usercfg->{users}->{$username};
    my $token_info = $user->{tokens}->{$token};

    my $ctime = time();
    die "token '$token' access expired\n"
        if $token_info->{expire} && ($token_info->{expire} < $ctime);

    die "invalid token value!\n" if !PVE::Cluster::verify_token($tokenid, $value);

    return wantarray ? ($tokenid) : $tokenid;
}

my $assemble_short_lived_ticket = sub {
    my ($prefix, $username, $path, $additional_secret) = @_;

    my $rsa_priv = get_privkey();

    $path = normalize_path($path);

    die "invalid ticket path\n" if !defined($path);

    my $secret_data = "$username:$path";
    $secret_data .= ":$additional_secret" if defined($additional_secret);

    return PVE::Ticket::assemble_rsa_ticket($rsa_priv, $prefix, undef, $secret_data);
};

my $verify_short_lived_ticket = sub {
    my ($ticket, $prefix, $username, $path, $additional_secret, $noerr) = @_;

    $path = normalize_path($path);

    die "invalid ticket path\n" if !defined($path);

    my $secret_data = "$username:$path";
    $secret_data .= ":$additional_secret" if defined($additional_secret);

    my ($rsa_pub, $rsa_mtime) = get_pubkey();
    if (!$rsa_pub || (time() - $rsa_mtime > $authkey_lifetime && $authkey_lifetime > 0)) {
        if ($noerr) {
            return undef;
        } else {
            # raise error via undef ticket
            PVE::Ticket::verify_rsa_ticket($rsa_pub, $prefix);
        }
    }

    return PVE::Ticket::verify_rsa_ticket($rsa_pub, $prefix, $ticket, $secret_data, -20, 40,
        $noerr);
};

# VNC tickets
# - they do not contain the username in plain text
# - they are restricted to a specific resource path (example: '/vms/100') and port
sub assemble_vnc_ticket {
    my ($username, $path, $port) = @_;

    return $assemble_short_lived_ticket->('PVEVNC', $username, $path, $port);
}

sub verify_vnc_ticket {
    my ($ticket, $username, $path, $port, $noerr) = @_;

    # FIXME: MAJOR VERSION: Drop this, requiring using explicit 'password' return value for VNC API
    if ($ticket =~ /^.{8}:(PVEVNC:.*)\z/) {
        $ticket = $1;
    }

    return $verify_short_lived_ticket->($ticket, 'PVEVNC', $username, $path, $port, $noerr);
}

# Tunnel tickets
# - they do not contain the username in plain text
# - they are restricted to a specific resource path (example: '/vms/100', '/socket/run/qemu-server/123.storage')
sub assemble_tunnel_ticket {
    my ($username, $path) = @_;

    return $assemble_short_lived_ticket->('PVETUNNEL', $username, $path, undef);
}

sub verify_tunnel_ticket {
    my ($ticket, $username, $path, $noerr) = @_;

    return $verify_short_lived_ticket->($ticket, 'PVETUNNEL', $username, $path, undef, $noerr);
}

sub assemble_spice_ticket {
    my ($username, $vmid, $node, $port) = @_;

    my $secret = &$get_csrfr_secret();

    return PVE::Ticket::assemble_spice_ticket($secret, $username, $vmid, $node, $port);
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

    # remote-viewer wants comma as separator (not '/')
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

    my ($ticket, $proxyticket) = assemble_spice_ticket($authuser, $vmid, $node, $port);

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

    if (!$data->{enable}) {
        die "user '$username' is disabled\n" if !$noerr;
        return undef;
    }

    my $ctime = time();
    my $expire = $usercfg->{users}->{$username}->{expire};

    if ($expire && $expire < $ctime) {
        die "user '$username' access expired\n" if !$noerr;
        return undef;
    }

    return 1; # enabled and not expired
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

# deprecated
sub verify_one_time_pw {
    my ($type, $username, $keys, $tfa_cfg, $otp) = @_;

    die "missing one time password for two-factor authentication '$type'\n" if !$otp;

    # fixme: proxy support?
    my $proxy;

    if ($type eq 'yubico') {
        PVE::OTP::yubico_verify_otp(
            $otp, $keys, $tfa_cfg->{url}, $tfa_cfg->{id}, $tfa_cfg->{key}, $proxy,
        );
    } elsif ($type eq 'oath') {
        PVE::OTP::oath_verify_otp($otp, $keys, $tfa_cfg->{step}, $tfa_cfg->{digits});
    } else {
        die "unknown tfa type '$type'\n";
    }
}

# password should be utf8 encoded
# Note: some plugins delay/sleep if auth fails
sub authenticate_user : prototype($$$;$) {
    my ($username, $password, $otp, $tfa_challenge) = @_;

    die "no username specified\n" if !$username;

    my ($ruid, $realm);

    ($username, $ruid, $realm) = PVE::Auth::Plugin::verify_username($username);

    my $usercfg = cfs_read_file('user.cfg');

    check_user_enabled($usercfg, $username);

    my $domain_cfg = cfs_read_file('domains.cfg');

    my $cfg = $domain_cfg->{ids}->{$realm};
    die "auth domain '$realm' does not exist\n" if !$cfg;
    my $plugin = PVE::Auth::Plugin->lookup($cfg->{type});

    if ($tfa_challenge) {
        # This is the 2nd factor, use the password for the OTP response.
        my $tfa_challenge = authenticate_2nd_new($username, $realm, $password, $tfa_challenge);
        return wantarray ? ($username, $tfa_challenge) : $username;
    }

    $plugin->authenticate_user($cfg, $realm, $ruid, $password);

    # This is the first factor with an optional immediate 2nd factor for TOTP:
    $tfa_challenge = authenticate_2nd_new($username, $realm, $otp, undef);
    return wantarray ? ($username, $tfa_challenge) : $username;
}

sub authenticate_2nd_new_do : prototype($$$$) {
    my ($username, $realm, $tfa_response, $tfa_challenge) = @_;
    my ($tfa_cfg, $realm_tfa) = user_get_tfa($username, $realm);

    # FIXME: `$tfa_cfg` is now usually never undef - use cheap check for
    # whether the user has *any* entries here instead whe it is available in
    # pve-rs
    if (!defined($tfa_cfg)) {
        # Fail closed: a challenge response cannot be verified without a TFA
        # config, and a realm requiring TFA must never silently get none.
        die "no TFA configuration available for user '$username'\n"
            if defined($tfa_challenge) || defined($tfa_response) || $realm_tfa;

        return undef;
    }

    my $realm_type = $realm_tfa && $realm_tfa->{type};
    # verify realm type unless using recovery keys:
    if (defined($realm_type)) {
        $realm_type = 'totp' if $realm_type eq 'oath'; # we used to call it that
        if ($realm_type eq 'yubico') {
            # Yubico auth will not be supported in rust for now...
            if (!defined($tfa_challenge)) {
                my $challenge = { yubico => JSON::true };
                # Even with yubico auth we do allow recovery keys to be used:
                if (my $recovery = $tfa_cfg->recovery_state($username)) {
                    $challenge->{recovery} = $recovery;
                }
                return to_json($challenge);
            }

            if ($tfa_response =~ /^yubico:(.*)\z/) {
                $tfa_response = $1;
                # Defer to after unlocking the TFA config:
                return sub {
                    authenticate_yubico_new(
                        $tfa_cfg, $username, $realm_tfa, $tfa_challenge, $tfa_response,
                    );
                };
            }
        }

        my $response_type;
        if (defined($tfa_response)) {
            if ($tfa_response !~ /^([^:]+):/) {
                die "bad otp response\n";
            }
            $response_type = $1;
        }

        die "realm requires $realm_type authentication\n"
            if $response_type && $response_type ne 'recovery' && $response_type ne $realm_type;
    }

    configure_u2f_and_wa($tfa_cfg);

    my ($result, $tfa_done);
    if (defined($tfa_challenge)) {
        $tfa_done = 1;
        $tfa_challenge = verify_ticket($tfa_challenge, 0, $username);
        $result = $tfa_cfg->authentication_verify2($username, $tfa_challenge, $tfa_response);
        $tfa_challenge = undef;
    } else {
        $tfa_challenge = $tfa_cfg->authentication_challenge($username);

        die "missing required 2nd keys\n"
            if $realm_tfa && !defined($tfa_challenge);

        if (defined($tfa_response)) {
            if (defined($tfa_challenge)) {
                $tfa_done = 1;
                $result =
                    $tfa_cfg->authentication_verify2($username, $tfa_challenge, $tfa_response);
            } else {
                die "no such challenge\n";
            }
        }
    }

    if ($tfa_done) {
        if (!$result) {
            # authentication_verify2 somehow returned undef - should be unreachable
            die "2nd factor failed\n";
        }

        if ($result->{'needs-saving'}) {
            cfs_write_file('priv/tfa.cfg', $tfa_cfg);
        }
        if ($result->{'totp-limit-reached'}) {
            # FIXME: send mail to the user (or admin/root if no email configured)
            die "failed 2nd factor: TOTP limit reached, locked\n";
        }
        if ($result->{'tfa-limit-reached'}) {
            # FIXME: send mail to the user (or admin/root if no email configured)
            die "failed 1nd factor: TFA limit reached, user locked out\n";
        }
        if (!$result->{result}) {
            die "failed 2nd factor\n";
        }
    }

    return $tfa_challenge;
}

# Returns a tfa challenge or undef.
sub authenticate_2nd_new : prototype($$$$) {
    my ($username, $realm, $tfa_response, $tfa_challenge) = @_;

    my $result;

    if (defined($tfa_response) && $tfa_response =~ m/^recovery:/) {
        $result = lock_tfa_config(sub {
            authenticate_2nd_new_do($username, $realm, $tfa_response, $tfa_challenge);
        });
    } else {
        $result = authenticate_2nd_new_do($username, $realm, $tfa_response, $tfa_challenge);
    }

    # Yubico auth returns the authentication sub:
    if (ref($result) eq 'CODE') {
        $result = $result->();
    }

    return $result;
}

sub authenticate_yubico_new : prototype($$$) {
    my ($tfa_cfg, $username, $realm, $tfa_challenge, $otp) = @_;

    $tfa_challenge = verify_ticket($tfa_challenge, 0, $username);
    $tfa_challenge = from_json($tfa_challenge);

    if (!$tfa_challenge->{yubico}) {
        die "no such challenge\n";
    }

    my $keys = $tfa_cfg->get_yubico_keys($username);
    die "no keys configured\n" if !defined($keys) || !length($keys);

    authenticate_yubico_do($otp, $keys, $realm);

    # return `undef` to clear the tfa challenge.
    return undef;
}

sub authenticate_yubico_do : prototype($$$) {
    my ($value, $keys, $realm) = @_;

    # fixme: proxy support?
    my $proxy = undef;

    PVE::OTP::yubico_verify_otp($value, $keys, $realm->{url}, $realm->{id}, $realm->{key}, $proxy);
}

sub configure_u2f_and_wa : prototype($) {
    my ($tfa_cfg) = @_;

    my $rpc_origin;
    my $get_origin = sub {
        return $rpc_origin if defined($rpc_origin);
        my $rpcenv = PVE::RPCEnvironment::get();
        if (my $origin = $rpcenv->get_request_host(1)) {
            $rpc_origin = "https://$origin";
            return $rpc_origin;
        }
        die "failed to figure out origin\n";
    };

    my $dc = cfs_read_file('datacenter.cfg');
    if (my $u2f = $dc->{u2f}) {
        eval {
            $tfa_cfg->set_u2f_config({
                origin => $u2f->{origin} // $get_origin->(),
                appid => $u2f->{appid},
            });
        };
        warn "u2f unavailable, configuration error: $@\n" if $@;
    }
    if (my $wa = $dc->{webauthn}) {
        $wa->{origin} //= $get_origin->();
        eval { $tfa_cfg->set_webauthn_config({%$wa}) };
        warn "webauthn unavailable, configuration error: $@\n" if $@;
    }
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

sub iterate_acl_tree {
    my ($path, $node, $code) = @_;

    $code->($path, $node);

    $path = '' if $path eq '/'; # avoid leading '//'

    my $children = $node->{children};

    foreach my $child (sort keys %$children) {
        iterate_acl_tree("$path/$child", $children->{$child}, $code);
    }
}

# recursively checks a node and all its children for active permissions
sub acl_tree_has_permissions {
    my ($node) = @_;

    for my $key (keys %$node) {
        if ($key ne 'children') {
            return 1;
        }
    }

    for my $child_key (keys $node->{children}->%*) {
        if (acl_tree_has_permissions($node->{children}->{$child_key})) {
            return 1;
        }
    }

    return 0;
}

# find ACL node corresponding to normalized $path under $root
sub find_acl_tree_node {
    my ($root, $path) = @_;

    my $split_path = [split("/", $path)];

    if (!$split_path) {
        return $root;
    }

    my $node = $root;
    for my $p (@$split_path) {
        next if !$p;

        $node->{children} = {} if !$node->{children};
        $node->{children}->{$p} = {} if !$node->{children}->{$p};

        $node = $node->{children}->{$p};
    }

    return $node;
}

=head3 find_acl_tree_node_parent($root, $path)

Finds an ACL node by path C<$path> starting from the root node
C<$root>, without autovivifying (creating) missing nodes.
Returns a list containing the parent node, the final path
segment, and the target node itself.

=cut

sub find_acl_tree_node_parent {
    my ($root, $path) = @_;

    my $current = $root;
    my $parent = undef;
    my $last_key = undef;

    my @split_path = split('/', $path);

    for my $segment (@split_path) {
        if (defined($current->{children}) && defined($current->{children}->{$segment})) {
            $parent = $current;
            $last_key = $segment;
            $current = $current->{children}->{$segment};
        } else {
            return (undef, undef, undef);
        }
    }

    return ($parent, $last_key, $current);
}

sub add_user_group {
    my ($username, $usercfg, $group) = @_;

    $usercfg->{users}->{$username}->{groups}->{$group} = 1;
    $usercfg->{groups}->{$group}->{users}->{$username} = 1;
}

sub delete_user_group {
    my ($username, $usercfg) = @_;

    foreach my $group (keys %{ $usercfg->{groups} }) {

        delete($usercfg->{groups}->{$group}->{users}->{$username})
            if $usercfg->{groups}->{$group}->{users}->{$username};
    }
}

sub delete_user_acl {
    my ($username, $usercfg) = @_;

    my $code = sub {
        my ($path, $acl_node) = @_;

        delete($acl_node->{users}->{$username})
            if $acl_node->{users}->{$username};
    };

    iterate_acl_tree("/", $usercfg->{acl_root}, $code);
}

sub delete_group_acl {
    my ($group, $usercfg) = @_;

    my $code = sub {
        my ($path, $acl_node) = @_;

        delete($acl_node->{groups}->{$group})
            if $acl_node->{groups}->{$group};
    };

    iterate_acl_tree("/", $usercfg->{acl_root}, $code);
}

sub delete_pool_acl {
    my ($pool, $usercfg) = @_;

    delete($usercfg->{acl_root}->{children}->{pool}->{children}->{$pool});
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
            'VM.GuestAgent.Unrestricted',
            'VM.Migrate',
            'VM.Replicate',
            'VM.Snapshot',
            'VM.Snapshot.Rollback',
        ],
        user => [
            'VM.Config.CDROM', # change CDROM media
            'VM.Config.Cloudinit',
            'VM.Console',
            'VM.Backup',
            'VM.GuestAgent.FileRead',
            'VM.GuestAgent.FileSystemMgmt',
            'VM.GuestAgent.FileWrite',
            'VM.PowerMgmt',
        ],
        audit => [
            'VM.Audit', 'VM.GuestAgent.Audit',
        ],
    },
    Sys => {
        root => [
            'Sys.PowerMgmt',
            'Sys.Modify', # edit/change node settings
            'Sys.Incoming', # incoming storage/guest migrations
            'Sys.AccessNetwork', # for, e.g., downloading ISOs from any URL
        ],
        admin => [
            'Sys.Console', 'Sys.Syslog',
        ],
        user => [],
        audit => [
            'Sys.Audit',
        ],
    },
    Datastore => {
        root => [],
        admin => [
            'Datastore.Allocate', 'Datastore.AllocateTemplate',
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
            'SDN.Allocate', 'SDN.Audit',
        ],
        user => [
            'SDN.Use',
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
        user => [
            'Pool.Audit',
        ],
        audit => [
            'Pool.Audit',
        ],
    },
    Mapping => {
        root => [],
        admin => [
            'Mapping.Modify',
        ],
        user => [
            'Mapping.Use',
        ],
        audit => [
            'Mapping.Audit',
        ],
    },
};

my $valid_privs = {
    'Permissions.Modify' => 1, # not contained in a group
};

my $special_roles = {
    'NoAccess' => {}, # no privileges
    'Administrator' => $valid_privs, # all privileges
};

sub create_roles {

    for my $cat (keys %$privgroups) {
        my $cd = $privgroups->{$cat};
        # create map to easily check if a privilege is valid
        for my $priv (@{ $cd->{root} }, @{ $cd->{admin} }, @{ $cd->{user} }, @{ $cd->{audit} }) {
            $valid_privs->{$priv} = 1;
        }
        # create grouped admin roles and PVEAdmin
        for my $priv (@{ $cd->{admin} }, @{ $cd->{user} }, @{ $cd->{audit} }) {
            $special_roles->{"PVE${cat}Admin"}->{$priv} = 1;
            $special_roles->{"PVEAdmin"}->{$priv} = 1;
        }
        # create grouped user and audit roles
        if (scalar(@{ $cd->{user} })) {
            for my $priv (@{ $cd->{user} }, @{ $cd->{audit} }) {
                $special_roles->{"PVE${cat}User"}->{$priv} = 1;
            }
        }
        for my $priv (@{ $cd->{audit} }) {
            $special_roles->{"PVEAuditor"}->{$priv} = 1;
        }
    }

    # remove Mapping.Modify from PVEAdmin, only Administrator, root@pam and
    # PVEMappingAdmin should be able to use that for now
    delete $special_roles->{"PVEAdmin"}->{"Mapping.Modify"};

    $special_roles->{"PVETemplateUser"} = { 'VM.Clone' => 1, 'VM.Audit' => 1 };
}

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
        if (defined($valid_privs->{$priv})) {
            $usercfg->{roles}->{$role}->{$priv} = 1;
        } else {
            die "invalid privilege '$priv'\n";
        }
    }
}

sub lookup_username {
    my ($username, $noerr) = @_;

    $username =~ m!^(${PVE::Auth::Plugin::user_regex})\@(${PVE::Auth::Plugin::realm_regex})\z!;

    my $realm = $2;
    my $domain_cfg = cfs_read_file("domains.cfg");
    my $casesensitive = $domain_cfg->{ids}->{$realm}->{'case-sensitive'} // 1;

    if (!$casesensitive) {
        my $usercfg = cfs_read_file('user.cfg');
        my @matches = grep { lc $username eq lc $_ } (keys %{ $usercfg->{users} });

        die
            "ambiguous case insensitive match of username '$username', cannot safely grant access!\n"
            if scalar @matches > 1 && !$noerr;

        return $matches[0] if defined($matches[0]);
    }

    return $username;
}

sub normalize_path {
    my $path = shift;

    return undef if !$path;

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
	|/access/groups/[[:alnum:]\.\-\_]+
	|/access/realm
	|/access/realm/[[:alnum:]\.\-\_]+
	|/nodes
	|/nodes/[[:alnum:]\.\-\_]+
	|/nodes/[[:alnum:]\.\-\_]+/certificates
	|/pool
	|/pool/[A-Za-z0-9\.\-_]+(?:/[A-Za-z0-9\.\-_]+){0,2}
	|/sdn
	|/sdn/controllers
	|/sdn/controllers/[[:alnum:]\_\-]+
	|/sdn/dns
	|/sdn/dns/[[:alnum:]]+
	|/sdn/fabrics
	|/sdn/fabrics/[[:alnum:]]+
	|/sdn/ipams
	|/sdn/ipams/[[:alnum:]]+
	|/sdn/prefix-lists
	|/sdn/prefix-lists/[[:alnum:]]+
	|/sdn/route-maps
	|/sdn/route-maps/[[:alnum:]]+
	|/sdn/zones
	|/sdn/zones/[[:alnum:]\.\-\_]+
	|/sdn/zones/[[:alnum:]\.\-\_]+/[[:alnum:]\.\-\_]+
	|/sdn/zones/[[:alnum:]\.\-\_]+/[[:alnum:]\.\-\_]+/[1-9][0-9]{0,3}
	|/storage
	|/storage/[[:alnum:]\.\-\_]+
	|/vms
	|/vms/[1-9][0-9]{2,}
	|/mapping
	|/mapping/[[:alnum:]\.\-\_]+
	|/mapping/[[:alnum:]\.\-\_]+/[[:alnum:]\.\-\_]+
    )\z!xs;
}

PVE::JSONSchema::register_format('pve-groupid', \&verify_groupname);

sub verify_groupname {
    my ($groupname, $noerr) = @_;

    if ($groupname !~ m/^$PVE::Auth::Plugin::groupname_regex\z/) {

        die "group name '$groupname' contains invalid characters\n" if !$noerr;

        return undef;
    }

    return $groupname;
}

PVE::JSONSchema::register_format('pve-roleid', \&verify_rolename);

sub verify_rolename {
    my ($rolename, $noerr) = @_;

    if ($rolename !~ m/^[A-Za-z0-9\.\-_]+\z/) {

        die "role name '$rolename' contains invalid characters\n" if !$noerr;

        return undef;
    }

    return $rolename;
}

PVE::JSONSchema::register_format('pve-poolid', \&verify_poolname);

sub verify_poolname {
    my ($poolname, $noerr) = @_;

    if (split("/", $poolname) > 3) {
        die "pool name '$poolname' nested too deeply (max levels = 3)\n" if !$noerr;

        return undef;
    }

    # also adapt check_path above if changed!
    if ($poolname !~ m!^[A-Za-z0-9\.\-_]+(?:/[A-Za-z0-9\.\-_]+){0,2}\z!) {
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

    # add (empty) ACL tree root node
    if (!$cfg->{acl_root}) {
        $cfg->{acl_root} = {};
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

        foreach my $d (split(/:/, $line)) {
            $d =~ s/^\s+//;
            $d =~ s/\s+$//;
            push @data, $d;
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
                warn
                    "user config - ignore user '$user' - (illegal characters in expire '$expire')\n";
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
                if (defined($valid_privs->{$priv})) {
                    $cfg->{roles}->{$role}->{$priv} = 1;
                } else {
                    warn "user config - ignore invalid privilege '$priv'\n";
                }
            }

        } elsif ($et eq 'acl') {
            my ($propagate, $pathtxt, $uglist, $rolelist) = @data;

            $propagate = $propagate ? 1 : 0;

            if (my $path = normalize_path($pathtxt)) {
                my $acl_node;
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
                            $acl_node = find_acl_tree_node($cfg->{acl_root}, $path) if !$acl_node;
                            $acl_node->{groups}->{$group}->{$role} = $propagate;
                        } elsif (PVE::Auth::Plugin::verify_username($ug, 1)) {
                            if (!$cfg->{users}->{$ug}) { # user does not exist
                                warn "user config - ignore invalid acl member '$ug'\n";
                            }
                            $acl_node = find_acl_tree_node($cfg->{acl_root}, $path) if !$acl_node;
                            $acl_node->{users}->{$ug}->{$role} = $propagate;
                        } elsif (my ($user, $token) = split_tokenid($ug, 1)) {
                            if (check_token_exist($cfg, $user, $token, 1)) {
                                $acl_node = find_acl_tree_node($cfg->{acl_root}, $path)
                                    if !$acl_node;
                                $acl_node->{tokens}->{$ug}->{$role} = $propagate;
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
            my ($pool, $comment, $vmlist, $storelist, $networklist) = @data;

            if (!verify_poolname($pool, 1)) {
                warn "user config - ignore pool '$pool' - invalid characters in pool name\n";
                next;
            }

            # make sure to add the pool (even if there are no members)
            $cfg->{pools}->{$pool} = { vms => {}, storage => {}, pools => {}, network => {} }
                if !$cfg->{pools}->{$pool};

            if ($pool =~ m!/!) {
                my $curr = $pool;
                while ($curr =~ m!^(.+)/[^/]+$!) {
                    # ensure nested pool info is correctly recorded
                    my $parent = $1;
                    $cfg->{pools}->{$curr}->{parent} = $parent;

                    if (!$cfg->{pools}->{$parent}) {
                        $cfg->{pools}->{$parent} =
                            { vms => {}, storage => {}, pools => {}, network => {} };
                    }

                    $cfg->{pools}->{$parent}->{pools}->{$curr} = 1;
                    $curr = $parent;
                }
            }

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
            for my $network (split_list($networklist)) {

                if ($network !~ m/^[a-z0-9][a-z0-9\-_]*(?:\/[a-z0-9][a-z0-9\-_]*)*(?:\/\*)?$/i) {
                    warn "user config - ignore invalid sdn resource entry '$network' in pool"
                        . " '$pool'\n";
                    next;
                }

                $cfg->{pools}->{$pool}->{network}->{$network} = 1;
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
                warn
                    "user config - ignore token '$tokenid' - (illegal characters in expire '$expire')\n";
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

    foreach my $user (sort keys %{ $cfg->{users} }) {
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

    foreach my $group (sort keys %{ $cfg->{groups} }) {
        my $d = $cfg->{groups}->{$group};
        my $list = join(',', sort keys %{ $d->{users} });
        my $comment = $d->{comment} ? PVE::Tools::encode_text($d->{comment}) : '';
        $data .= "group:$group:$list:$comment:\n";
    }

    $data .= "\n";

    foreach my $pool (sort keys %{ $cfg->{pools} }) {
        my $d = $cfg->{pools}->{$pool};
        my $vmlist = join(',', sort keys %{ $d->{vms} });
        my $storelist = join(',', sort keys %{ $d->{storage} });
        my $networklist = join(',', sort keys %{ $d->{network} });
        my $comment = $d->{comment} ? PVE::Tools::encode_text($d->{comment}) : '';
        $data .= "pool:$pool:$comment:$vmlist:$storelist:$networklist:\n";
    }

    $data .= "\n";

    foreach my $role (sort keys %{ $cfg->{roles} }) {
        next if $special_roles->{$role};

        my $d = $cfg->{roles}->{$role};
        my $list = join(',', sort keys %$d);
        $data .= "role:$role:$list:\n";
    }

    $data .= "\n";

    my $collect_rolelist_members = sub {
        my ($acl_members, $result, $prefix, $exclude) = @_;

        foreach my $member (keys %$acl_members) {
            next if $exclude && $member eq $exclude;

            my $l0 = '';
            my $l1 = '';
            foreach my $role (sort keys %{ $acl_members->{$member} }) {
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

    iterate_acl_tree(
        "/",
        $cfg->{acl_root},
        sub {
            my ($path, $d) = @_;

            my $rolelist_members = {};

            $collect_rolelist_members->($d->{'groups'}, $rolelist_members, '@');

            # no need to save 'root@pam', it is always 'Administrator'
            $collect_rolelist_members->($d->{'users'}, $rolelist_members, '', 'root@pam');

            $collect_rolelist_members->($d->{'tokens'}, $rolelist_members, '');

            foreach my $propagate (0, 1) {
                my $filtered = $rolelist_members->{$propagate};
                foreach my $rolelist (sort keys %$filtered) {
                    my $uglist = join(',', sort keys %{ $filtered->{$rolelist} });
                    $data .= "acl:$propagate:$path:$uglist:$rolelist:\n";
                }

            }
        },
    );

    return $data;
}

# Creates a `PVE::RS::TFA` instance from the raw config data.
# Its contained hash will also support the legacy functionality.
sub parse_priv_tfa_config {
    my ($filename, $raw) = @_;

    $raw = '' if !defined($raw);
    my $cfg = PVE::RS::TFA->new($raw);

    # Purge invalid users:
    foreach my $user ($cfg->users()->@*) {
        my (undef, undef, $realm) = PVE::Auth::Plugin::verify_username($user, 1);
        if (!$realm) {
            warn "user tfa config - ignore user '$user' - invalid user name\n";
            $cfg->remove_user($user);
        }
    }

    return $cfg;
}

sub write_priv_tfa_config {
    my ($filename, $cfg) = @_;

    return $cfg->write();
}

sub roles {
    my ($cfg, $user, $path) = @_;

    # NOTE: we do not consider pools here.
    # NOTE: for privsep tokens, this does not filter roles by those that the
    # corresponding user has.
    # Use $rpcenv->permission() for any actual permission checks!

    return 'Administrator' if $user eq 'root@pam'; # root can do anything

    if (!defined($path)) {
        # this shouldn't happen!
        warn "internal error: ACL check called for undefined ACL path!\n";
        return {};
    }

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

    my $split = [split("/", $path)];
    if ($path eq '/') {
        $split = [''];
    }

    my $acl = $cfg->{acl_root};
    my $i = 0;

    while (@$split) {
        my $p = shift @$split;
        my $final = !@$split;
        if ($p ne '') {
            $acl = $acl->{children}->{$p};
        }

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
        foreach my $g (keys %{ $acl->{groups} }) {
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

    return { 'NoAccess' => $roles->{NoAccess} } if defined($roles->{NoAccess});
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

        if (my $acl = $usercfg->{acl_root}->{children}->{vms}->{children}->{$vmid}) {
            delete $usercfg->{acl_root}->{children}->{vms}->{children}->{$vmid};
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

        if (my $acl = $usercfg->{acl_root}->{children}->{storage}->{children}->{$storeid}) {
            delete $usercfg->{acl_root}->{children}->{storage}->{children}->{$storeid};
            $modified = 1;
        }
        foreach my $pool (keys %{ $usercfg->{pools} }) {
            delete $usercfg->{pools}->{$pool}->{storage}->{$storeid};
            $modified = 1;
        }
        cfs_write_file("user.cfg", $usercfg) if $modified;
    };

    lock_user_config(
        $deleteStorageAccessFn,
        "access permissions cleanup for storage $storeid failed",
    );
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

sub remove_vnets_from_pool {
    my ($paths) = @_;

    my $del_vnet_from_pool_fn = sub {
        my $usercfg = cfs_read_file("user.cfg");
        my $modified = 0;

        for my $pool (keys $usercfg->{pools}->%*) {
            my $pool_cfg = $usercfg->{pools}->{$pool};

            my @to_delete = ();

            for my $net_key (keys $pool_cfg->{network}->%*) {
                for my $path (@$paths) {
                    my (undef, $zone, $vnet) = split('/', $path);
                    my $network_key = "vnet/$zone/$vnet";

                    if ($net_key =~ m!^\Q$network_key\E(?:/(?:[0-9]+|\*))?\z!) {
                        push(@to_delete, $net_key);
                        last; # match skip ahead
                    }
                }
            }

            if (@to_delete) {
                for my $del_key (@to_delete) {
                    delete $pool_cfg->{network}->{$del_key};
                }
                $modified = 1;
            }

        }
        if ($modified) {
            cfs_write_file("user.cfg", $usercfg);
        }
    };

    lock_user_config($del_vnet_from_pool_fn, "pool cleanup for VNet failed");
}

sub migrate_vnet_zone_in_pool {
    my ($move_paths) = @_;

    my $update_vnet_zone_fn = sub {
        my $usercfg = cfs_read_file("user.cfg");
        my $modified = 0;

        my %move_map = ();
        for my $move ($move_paths->@*) {
            my $src_key = $move->{src_path};
            my $dest_key = $move->{dest_path};

            $src_key =~ s!^zones/!vnet/!;
            $dest_key =~ s!^zones/!vnet/!;

            if ($src_key ne $dest_key) {
                $move_map{$src_key} = $dest_key;
            }

        }

        for my $pool (keys $usercfg->{pools}->%*) {
            my $pool_cfg = $usercfg->{pools}->{$pool};

            my @to_delete = ();
            my %to_add = ();

            for my $net_key (sort keys $pool_cfg->{network}->%*) {
                if ($net_key =~ m!^(vnet/[^/]+/[^/]+)(?:/([0-9]+|\*))?\z!) {
                    my $base_key = $1;
                    my $vlan = $2;

                    if (my $new_base = $move_map{$base_key}) {
                        push(@to_delete, $net_key);

                        my $target_key = $new_base;
                        $target_key .= "/$vlan" if defined($vlan);

                        $to_add{$target_key} = $pool_cfg->{network}->{$net_key};
                    }
                }
            }

            if (@to_delete || keys %to_add) {
                for my $delete_key (@to_delete) {
                    delete $pool_cfg->{network}->{$delete_key};
                }

                for my $add_key (sort keys %to_add) {
                    $pool_cfg->{network}->{$add_key} = $to_add{$add_key};
                }

                $modified = 1;
            }
        }

        if ($modified) {
            cfs_write_file("user.cfg", $usercfg);
        }
    };

    lock_user_config($update_vnet_zone_fn, "pool update for VNets failed");
}

sub remove_sdn_resource_access {
    my ($paths) = @_; # [ 'zones/<zone>', 'zones/<zone>/<vnet>' ]

    my $delete_resource_fn = sub {
        my $usercfg = cfs_read_file("user.cfg");
        my $modified = 0;

        for my $path (@$paths) {
            my $full_path = "sdn/$path";

            my $current = $usercfg->{acl_root};
            my ($parent, $last_key) = find_acl_tree_node_parent($current, $full_path);

            if ($parent && $last_key) {
                delete $parent->{children}->{$last_key};
                $modified = 1;
            }
        }

        if ($modified) {
            cfs_write_file("user.cfg", $usercfg);
        }
    };

    lock_user_config($delete_resource_fn, "SDN ACL cleanup failed");
}

sub migrate_sdn_resource_access {
    my ($migrations) = @_;
    # [ { src_path => 'zones/<zoney>/<vnet>', dest_path => 'zones/<zonex>/<vnet>' } ]

    return if !$migrations;

    my $migrate_fn = sub {
        my $usercfg = cfs_read_file("user.cfg");

        my @prepared_moves = ();
        for my $migration (@$migrations) {

            my $invalid_key = 0;

            for my $key (qw(src_path dest_path)) {
                if (!defined($migration->{$key})) {
                    warn "Missing '$key' in migration entry.\n";
                    $invalid_key = 1;
                    last;
                }
            }

            next if $invalid_key;

            my $src_path = "sdn/$migration->{src_path}";
            my $dest_path = "sdn/$migration->{dest_path}";

            my ($src_parent, $src_last_key, $acl_node) =
                find_acl_tree_node_parent($usercfg->{acl_root}, $src_path);

            if (defined($src_parent) && defined($src_last_key) && defined($acl_node)) {
                # probe dest for conflicts
                my (undef, undef, $existing_dest_node) =
                    find_acl_tree_node_parent($usercfg->{acl_root}, $dest_path);

                if (acl_tree_has_permissions($existing_dest_node)) {
                    my $conflict_path = "/$dest_path";
                    my $source_path = "/$src_path";
                    die
                        "Destination '$conflict_path' already has permissions configured (Source:"
                        . " '$source_path'). Please remove the target ACLs manually before"
                        . " retrying.\n";
                }

                # stage move
                push(
                    @prepared_moves,
                    {
                        src_parent => $src_parent,
                        src_last_key => $src_last_key,
                        dest_path => $dest_path,
                        node => $acl_node,
                    },
                );
            }
        }

        return if !@prepared_moves;

        for my $move (@prepared_moves) {
            delete $move->{src_parent}->{children}->{ $move->{src_last_key} };

            my $current = $usercfg->{acl_root};
            my @dest_segments = split('/', $move->{dest_path});
            my $dest_last_key = pop @dest_segments;

            for my $segment (@dest_segments) {
                $current->{children}->{$segment} = {}
                    if !defined($current->{children}->{$segment});

                $current = $current->{children}->{$segment};
            }
            $current->{children}->{$dest_last_key} = $move->{node};

        }

        cfs_write_file("user.cfg", $usercfg);
    };

    lock_user_config($migrate_fn, "ACL migration failed");
}

my $USER_CONTROLLED_TFA_TYPES = {
    u2f => 1,
    oath => 1,
};

sub user_remove_tfa : prototype($) {
    my ($userid) = @_;

    my $tfa_cfg = cfs_read_file('priv/tfa.cfg');
    $tfa_cfg->remove_user($userid);
    cfs_write_file('priv/tfa.cfg', $tfa_cfg);
}

my sub add_old_yubico_keys : prototype($$$) {
    my ($userid, $tfa_cfg, $keys) = @_;

    my $count = 0;
    foreach my $key (split_list($keys)) {
        my $description = "<old userconfig key $count>";
        ++$count;
        $tfa_cfg->add_yubico_entry($userid, $description, $key);
    }
}

my sub normalize_totp_secret : prototype($) {
    my ($key) = @_;

    my $binkey;
    # See PVE::OTP::oath_verify_otp:
    if ($key =~ /^v2-0x([0-9a-fA-F]+)\z/) {
        # v2, hex
        $binkey = pack('H*', $1);
    } elsif ($key =~ /^v2-([A-Z2-7=]+)\z/) {
        # v2, base32
        $binkey = MIME::Base32::decode_rfc3548($1);
    } elsif ($key =~ /^[A-Z2-7=]{16}\z/) {
        $binkey = MIME::Base32::decode_rfc3548($key);
    } elsif ($key =~ /^[A-Fa-f0-9]{40}\z/) {
        $binkey = pack('H*', $key);
    } else {
        return undef;
    }

    return MIME::Base32::encode_rfc3548($binkey);
}

my sub add_old_totp_keys : prototype($$$$) {
    my ($userid, $tfa_cfg, $realm_tfa, $keys) = @_;

    my $issuer = 'Proxmox%20VE';
    my $account = uri_escape("Old key for $userid");
    my $digits = $realm_tfa->{digits} || 6;
    my $step = $realm_tfa->{step} || 30;
    my $uri = "otpauth://totp/$issuer:$account?digits=$digits&period=$step&algorithm=SHA1&secret=";

    my $count = 0;
    foreach my $key (split_list($keys)) {
        $key = normalize_totp_secret($key);
        # and just skip invalid keys:
        next if !defined($key);

        my $description = "<old userconfig key $count>";
        ++$count;
        eval { $tfa_cfg->add_totp_entry($userid, $description, $uri . $key) };
        warn $@ if $@;
    }
}

sub add_old_keys_to_realm_tfa : prototype($$$$) {
    my ($userid, $tfa_cfg, $realm_tfa, $keys) = @_;

    # if there's no realm tfa configured, we don't know what the keys mean, so we just ignore
    # them...
    return if !$realm_tfa;

    my $type = $realm_tfa->{type};
    if ($type eq 'oath') {
        add_old_totp_keys($userid, $tfa_cfg, $realm_tfa, $keys);
    } elsif ($type eq 'yubico') {
        add_old_yubico_keys($userid, $tfa_cfg, $keys);
    } else {
        # invalid keys, we'll just drop them now...
    }
}

sub user_get_tfa : prototype($$$) {
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

    my $tfa_cfg = cfs_read_file('priv/tfa.cfg');
    if (defined($keys) && $keys !~ /^x(?:!.*)\z/) {
        add_old_keys_to_realm_tfa($username, $tfa_cfg, $realm_tfa, $keys);
    }

    return ($tfa_cfg, $realm_tfa);
}

# bash completion helpers

register_standard_option(
    'userid-completed',
    get_standard_option('userid', { completion => \&complete_username }),
);

sub complete_username {

    my $user_cfg = cfs_read_file('user.cfg');

    return [keys %{ $user_cfg->{users} }];
}

sub complete_group {

    my $user_cfg = cfs_read_file('user.cfg');

    return [keys %{ $user_cfg->{groups} }];
}

sub complete_realm {

    my $domain_cfg = cfs_read_file('domains.cfg');

    return [keys %{ $domain_cfg->{ids} }];
}

1;

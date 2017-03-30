package PVE::Auth::PAM;

use strict;
use warnings;

use PVE::Tools qw(run_command);
use PVE::Auth::Plugin;
use Authen::PAM qw(:constants);

use base qw(PVE::Auth::Plugin);

sub type {
    return 'pam';
}

sub options {
    return {
	default => { optional => 1 },
	comment => { optional => 1 },
	tfa => { optional => 1 },
    };
}

sub authenticate_user {
    my ($class, $config, $realm, $username, $password) = @_;

    # user (www-data) need to be able to read /etc/passwd /etc/shadow
    die "no password\n" if !$password;

    my $pamh = new Authen::PAM('common-auth', $username, sub {
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

    return 1;
}


sub store_password {
    my ($class, $config, $realm, $username, $password) = @_;

    my $cmd = ['usermod'];

    my $epw = PVE::Tools::encrypt_pw($password);

    push @$cmd, '-p', $epw, $username;

    run_command($cmd, errmsg => 'change password failed');
}

1;

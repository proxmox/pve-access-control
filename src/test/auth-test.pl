#!/usr/bin/perl -w

use strict;
use warnings;

use PVE::PTY;

use PVE::AccessControl;

my $username = shift;
die "Username missing" if !$username;

my $password = PVE::PTY::read_password('password: ');
PVE::AccessControl::authenticate_user($username, $password);

print "Authentication Successful!!\n";

exit(0);

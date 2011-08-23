#!/usr/bin/perl -w

use strict;
use Term::ReadLine;
use PVE::AccessControl;

my $username = shift;
die "Username missing" if !$username;
sub read_password {

    my $term = new Term::ReadLine ('pveum');
    my $attribs = $term->Attribs;
    $attribs->{redisplay_function} = $attribs->{shadow_redisplay};
    my $input = $term->readline('password: ');
    return $input;
}

my $password = read_password();
PVE::AccessControl::authenticate_user($username,$password);

print "Authentication Successful!!\n";

exit (0);

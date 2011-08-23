#!/usr/bin/perl -w 

use strict;
use PVE::AccessControl;

# create ticket using username and password
#my $ticket =  PVE::AccessControl::create_ticket(undef, $username, $password);

# create ticket using ident auth
my $login = getpwuid($<);
my $username = ($< == 0) ? 'root' : "$login\@localhost";
my $ticket = PVE::AccessControl::create_ticket(undef, $username);
print "got ticket using ident auth: $ticket\n";

for (my $i = 0; $i < 1; $i++) { 
    $ticket =  PVE::AccessControl::create_ticket($ticket, $username);
    print "renewed ticket: $ticket\n";
}

my $user = 'testuser';

PVE::AccessControl::add_user($ticket, $user, 'testpw');

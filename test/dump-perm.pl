#!/usr/bin/perl -w

use strict;
use PVE::RPCEnvironment;
use Getopt::Long;
use Data::Dumper;

# example: 
# dump-perm.pl -f myuser.cfg root /

my $opt_file;
if (!GetOptions ("file=s"   => \$opt_file)) {
    exit (-1);
}

my $username = shift;
my $path = shift;
 
if (!($username && $path)) {
    print "usage: $0 <username> <path>\n";
    exit (-1);
}

my $cfg;

my $rpcenv = PVE::RPCEnvironment->init('cli');
if ($opt_file) {
    $rpcenv->init_request(userconfig => $opt_file);
} else {
    $rpcenv->init_request();
}

my $perm = $rpcenv->permissions($username, $path);

print "permission for user '$username' on '$path':\n";
print join(',', keys %$perm) . "\n";

exit (0);

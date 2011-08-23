#!/usr/bin/perl -w

use strict;
use PVE::AccessControl;
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

if ($opt_file) {

    my $fh = IO::File->new ($opt_file, 'r') ||
	die "can't open file $opt_file - $!\n";

    $cfg = PVE::AccessControl::parse_config ($opt_file, $fh);
    $fh->close();

} else {
    $cfg = PVE::AccessControl::load_user_config();
}
my $perm = PVE::AccessControl::permission($cfg, $username, $path);

print "permission for user '$username' on '$path':\n";
print join(',', keys %$perm) . "\n";

exit (0);

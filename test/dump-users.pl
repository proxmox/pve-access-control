#!/usr/bin/perl -w

use strict;
use PVE::AccessControl;
use Data::Dumper;

my $cfg;

$cfg = PVE::AccessControl::load_user_config();

print Dumper($cfg) . "\n";

exit (0);

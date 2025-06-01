#!/usr/bin/perl -w

use strict;
use warnings;

use Data::Dumper;

use PVE::AccessControl;

my $cfg;

$cfg = PVE::AccessControl::load_user_config();

print Dumper($cfg) . "\n";

exit(0);

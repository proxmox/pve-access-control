#!/usr/bin/env perl

use strict;
use warnings;

use TAP::Harness;

my $harness = TAP::Harness->new({ verbosity => -1 });

my $result = $harness->runtests('api-get-permissions-test.pl');

exit -1 if $result->{failed};

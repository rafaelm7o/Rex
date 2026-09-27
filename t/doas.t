#!/usr/bin/env perl

use v5.14.4;
use warnings;

use Test::More tests => 7;
use Test::Warnings;

use Rex -feature => '1.4';
use Rex::Commands::Run;

# Test global doas state
Rex::global_doas(1);
ok( Rex::is_doas(), 'global doas is enabled' );

Rex::global_doas(0);
ok( !Rex::is_doas(), 'global doas is disabled' );

# Test global doas toggle
doas 'on';
ok( Rex::is_doas(), q{doas 'on' enables global doas} );

doas '0';
ok( !Rex::is_doas(), q{doas '0' disables global doas} );

# Test doas with code block
my $doas_called = 0;

doas sub {
  $doas_called = 1;
  Rex::is_doas();
};

ok( $doas_called, 'doas code block executed' );

# Test doas with hashref options
my $ret = doas {
  user    => 'testuser',
  command => 'echo test',
};

ok( defined $ret, 'doas with hashref returns result' );

done_testing;

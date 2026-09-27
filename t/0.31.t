#!/usr/bin/env perl

use v5.14.4;
use warnings;

our $VERSION = '9999.99.99_99'; # VERSION

use Test::More tests => 154;
use Test::Warnings;

use Rex -feature => '0.31';

delete $ENV{REX_USER};

user("root3");
password("pass3");
private_key("priv.key3");
public_key("pub.key3");

key_auth();

no warnings;
is( Rex::TaskList->create()->is_default_auth(), 0, "default auth off" );
use warnings;

group( "foo", "server1", "server2", "server3" );
group( "bar", "serv[01..10]" );

my @servers = Rex::Group->get_group("foo");
is( $servers[0], "server1", "get_group" );
is( $servers[2], "server3", "get_group" );

@servers = Rex::Group->get_group("bar");
@servers = $servers[0]->get_servers;
is( $servers[0], "serv01", "get_group with evaluation" );
is( $servers[5], "serv06", "get_group with evaluation" );

task( "authtest1", group => "foo", sub { } );
task( "authtest2", group => "bar", sub { } );
task( "authtest3", "srv001", sub { } );
task( "authtest4", group => "latebar", sub { } );
group( "latebar", "server[01..03]" );

my $task       = Rex::TaskList->create()->get_task("authtest3");
my @all_server = @{ $task->server };

for my $server (@all_server) {
  my $auth = $task->merge_auth($server);
  is( $auth->{user},        "root3",     "merge_auth - user" );
  is( $auth->{password},    "pass3",     "merge_auth - pass" );
  is( $auth->{public_key},  "pub.key3",  "merge_auth - pub" );
  is( $auth->{private_key}, "priv.key3", "merge_auth - priv" );
  is( $auth->{auth_type},   "key",       "merge_auth - auth" );
}

pass_auth();

for my $server (@all_server) {
  my $auth = $task->merge_auth($server);
  is( $auth->{user},        "root3",     "merge_auth - user" );
  is( $auth->{password},    "pass3",     "merge_auth - pass" );
  is( $auth->{public_key},  "pub.key3",  "merge_auth - pub" );
  is( $auth->{private_key}, "priv.key3", "merge_auth - priv" );
  is( $auth->{auth_type},   "pass",      "merge_auth - auth" );
}

auth( for => "bar",     user => "jan", password => "foo" );
auth( for => "latebar", user => "jan", password => "foo" );

$task       = Rex::TaskList->create()->get_task("authtest1");
@all_server = @{ $task->server };

for my $server (@all_server) {
  my $auth = $task->merge_auth($server);
  is( $auth->{user},        "root3",     "merge_auth - user" );
  is( $auth->{password},    "pass3",     "merge_auth - pass" );
  is( $auth->{public_key},  "pub.key3",  "merge_auth - pub" );
  is( $auth->{private_key}, "priv.key3", "merge_auth - priv" );
}

$task       = Rex::TaskList->create()->get_task("authtest2");
@all_server = @{ $task->server };

for my $server (@all_server) {
  my $auth = $task->merge_auth($server);
  is( $auth->{user},        "jan",       "merge_auth - user" );
  is( $auth->{password},    "foo",       "merge_auth - pass" );
  is( $auth->{public_key},  "pub.key3",  "merge_auth - pub" );
  is( $auth->{private_key}, "priv.key3", "merge_auth - priv" );
  is( $auth->{auth_type},   "try",       "merge_auth - auth_type" );
  ok( !$auth->{sudo}, "merge_auth - sudo" );
}

$task       = Rex::TaskList->create()->get_task("authtest4");
@all_server = @{ $task->server };

for my $server (@all_server) {
  my $auth = $task->merge_auth($server);
  is( $auth->{user},        "jan",       "merge_auth - user - lategroup" );
  is( $auth->{password},    "foo",       "merge_auth - pass - lategroup" );
  is( $auth->{public_key},  "pub.key3",  "merge_auth - pub - lategroup" );
  is( $auth->{private_key}, "priv.key3", "merge_auth - priv - lategroup" );
  is( $auth->{auth_type},   "try",       "merge_auth - auth_type - lategroup" );
  ok( !$auth->{sudo}, "merge_auth - sudo - lategroup" );
}

auth(
  for         => "authtest1",
  user        => "deploy",
  password    => "baz",
  private_key => FALSE(),
  public_key  => FALSE(),
  sudo        => TRUE()
);

$task       = Rex::TaskList->create()->get_task("authtest1");
@all_server = @{ $task->server };

for my $server (@all_server) {
  my $auth = $task->merge_auth($server);
  is( $auth->{user},        "deploy", "merge_auth - user" );
  is( $auth->{password},    "baz",    "merge_auth - pass" );
  is( $auth->{public_key},  FALSE(),  "merge_auth - pub" );
  is( $auth->{private_key}, FALSE(),  "merge_auth - priv" );
  is( $auth->{auth_type},   "pass",   "merge_auth - auth_type" );
  is( $auth->{sudo},        TRUE(),   "merge_auth - sudo" );
}

set( "key1", "val1" );
is( get("key1"), "val1", "got value of key1" );

set( "key1", "val2" );
is( get("key1"), "val2", "got new value of key1" );

set( "key2", [qw/one two three/] );
is( get("key2")->[0], "one",   "got value of first item in key2" );
is( get("key2")->[1], "two",   "got value of 2nd item in key2" );
is( get("key2")->[2], "three", "got value of 3rd item in key2" );

set( "key2", [qw/four five/] );
is( get("key2")->[0], "one",   "got value of first item in key2" );
is( get("key2")->[1], "two",   "got value of 2nd item in key2" );
is( get("key2")->[2], "three", "got value of 3rd item in key2" );
is( get("key2")->[3], "four",  "got value of NEW first item in key2" );
is( get("key2")->[4], "five",  "got value of NEW 2nd item in key2" );

set( "key3", { name => 'foo', surname => 'bar' } );
is( get("key3")->{name},    "foo", "got value of name parameter in key3" );
is( get("key3")->{surname}, "bar", "got value of surname parameter in key3" );

set( "key3", { x1 => 'x', x2 => 'xx' } );
is( get("key3")->{name},    "foo", "got value of name parameter in key3" );
is( get("key3")->{surname}, "bar", "got value of surname parameter in key3" );
is( get("key3")->{x1}, "x",  "got value of NEW name parameter x1 in key3" );
is( get("key3")->{x2}, "xx", "got value of NEW name parameter x2 in key3" );

# doas tests
group( "doasgroup", "doas01", "doas02" );
task( "doastest1", group => "doasgroup", sub { } );

auth(
  for      => "doasgroup",
  user     => "doasuser",
  password => "doaspass",
  doas     => TRUE()
);

$task       = Rex::TaskList->create()->get_task("doastest1");
@all_server = @{ $task->server };

for my $server (@all_server) {
  my $auth = $task->merge_auth($server);
  is( $auth->{user},     "doasuser", "merge_auth - doas user" );
  is( $auth->{password}, "doaspass", "merge_auth - doas password" );
  is( $auth->{doas},     TRUE(),     "merge_auth - doas enabled" );
  ok( !$auth->{sudo}, "merge_auth - sudo not set for doas" );
}

# Test global doas state
Rex::global_doas(1);
ok( Rex::is_doas(), "global doas is enabled" );
Rex::global_doas(0);
ok( !Rex::is_doas(), "global doas is disabled" );

# Test doas command function
use Rex::Commands;

# Test global doas toggle via doas command
doas "on";
ok( Rex::is_doas(), "doas 'on' enables global doas" );
doas "0";
ok( !Rex::is_doas(), "doas '0' disables global doas" );

# Test doas with code block
my $doas_called = 0;
doas sub { $doas_called = 1; Rex::is_doas(); };
ok( $doas_called, "doas code block executed" );

# Test doas with hashref options
my $ret = doas { user => 'testuser', command => 'echo test' };
ok( defined $ret, "doas with hashref returns result" );

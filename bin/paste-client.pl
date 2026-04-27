#!/usr/bin/perl

#
#   __ _  _  __   ___  __  ____ ____
#  /  ( \/ )/ _\ / __)/ _\/ ___(_  _)
# (  O )  (/    ( (_ /    \___ \ )(
#  \__(_/\_\_/\_/\___\_/\_(____/(__)
#
# By oxagast, thanks to termbin.org creators for the idea.
#
# Babe! Let me lick your butthole!
#
# usage: cat /etc/passwd | perl paste-client.pl

use strict;
use warnings;
use IO::Socket::SSL;
use Getopt::Long;
my $verify = "true";
my %options;
GetOptions(
           'server=s' => \$options{server},
           'port=i'   => \$options{port},
           'help'     => \$options{help},
           'noverify' => \$options{noverify}
);

if ($options{help}) {
  print STDERR "Usage: echo abc | $0 --server oxasploits.com --port 8866\n";
  exit 1;
}
STDIN->blocking(0);
my @data = <STDIN>;
if (@data) {
  my $host = 'spaste.oxasploits.com';
  my $port = 8866;
  if ($options{server}) {
    $host = $options{server};
  }
  if ($options{port}) {
    $port = $options{port};
  }

  my $sock = IO::Socket::SSL->new(
                                  PeerAddr            => "$host:$port",
                                  Proto               => 'tcp',
                                  SSL_verify_mode     => SSL_VERIFY_PEER,
                                  SSL_verifycn_name   => $host,
                                  SSL_hostname        => $host,
                                  SSL_verifycn_scheme => 'http',
                                  Timeout             => '8'
  ) or die "Error: Creation of socket: $!";
  print $sock @data;
  print $sock "\n";
  $sock->shutdown(1);
  my $count = 0;
  while(my $res = <$sock>) {
      if (($res =~ m|https://.*/p/.*|) || ($res =~ m/0x/)) {
      
      print $res;
      exit 0;
      if ($count == 2) { $sock->close(); exit 0 }
    }
    # elsif($res =~ m|<<END>>|) {
    #    $sock->close();
    #    exit 0;
    #}
    #  elsif($res =~ m|^0x|) {
    #    print $res;
    #exit 1;
    #}
    else {
      print STDERR "Error: This doesn't look like an spaste server!\n";
      exit 1;
    }
}
if (!defined $_) {
  print STDERR "Error: You should add your paste data to stdin.\n";
  print STDERR "Usage:\n  echo abc | $0 --server oxasploits.com --port 8888\n";
  exit 1;
}}

#!/usr/bin/perl

#
#   __ _  _  __   ___  __  ____ ____
#  /  ( \/ )/ _\ / __)/ _\/ ___(_  _)
# (  O )  (/    ( (_ /    \___ \ )(
#  \__(_/\_\_/\_/\___\_/\_(____/(__)
#
# By oxagast, thanks to termbin.org creators for the idea.
# I would suggest creating an ssl user and pastebot user for this for security reasons.
# Set the permissions on your valid cert.pm and privkey.pem and on the directory on the
# webserver.
#
# Babe! Let me lick your butthole!
#
# useage: ./paste-server.pl --conf spaste.conf

use strict;
use warnings;
use IO::Handle;
use Fcntl ("F_GETFL", "F_SETFL", "O_NONBLOCK");
use Socket;
use IO::Socket::SSL;
use threads;
use IO::Tee;
use Config::Tiny;
use Getopt::Long qw (GetOptions);
$SIG{TERM} = $SIG{INT} = sub {die "Caught a sigterm $!"};
STDOUT->autoflush();
STDERR->autoflush();
if ($#ARGV + 1 ne 2) {
  print STDERR
    "Incorrect number of arguments.\n Useage:\n  $ARGV[0] --conf [file]\n";
  exit $SIG{TERM};
}
if ($ARGV[0] !~ "--conf") {
  print STDERR "You need to specify a config file with --conf [file]\n";
  exit $SIG{TERM};
}
if (!-r $ARGV[1]) {
  print STDERR "The config file doesn't exist!";
  exit $SIG{TERM};
}
my (
  $logfile,  $pasteroot, $host,    $srvname, $port,
  $certfile, $keyfile,   $pidfile, $seclvl);
my $cfgf = undef;
GetOptions('conf=s' => \$cfgf);
my $config = Config::Tiny->read($cfgf);
$host      = $config->{Server}{fqdn};
$srvname   = $config->{Server}{baseuri};
$port      = $config->{Server}{listenport};
$certfile  = $config->{SSL}{certfile};
$keyfile   = $config->{SSL}{keyfile};
$pidfile   = $config->{Settings}{pidfile};
$pasteroot = $config->{Server}{pasteroot};
$logfile   = $config->{Settings}{logfile};    # log
$seclvl    = $config->{Settings}{seclvl};     # security level
my $ver = "v1.3.1";                           # hell yea, new revision!
                                              # can we have a party
                                              # with lots of hookers?
                                              # bonus points for anal beads

if (-e $pidfile) {
  die
"0x07 Error: SPaste is already running or the lockfile didn't get wiped!  If you are sure it is not running, remove $pidfile";
}
if ($srvname =~ m|http:|) {
  print STDERR
"0x09 Error: The baseuri should not be http! Only use a properly configured https server with a fqdn here!\n";
}
open(PIDF, ">", $pidfile) or die $!;
print PIDF $$ . "\n";
close(PIDF);
open(my $lfh, '>>', $logfile) or die $!;
my $tee = IO::Tee->new($lfh, \*STDOUT);
select $tee;
$lfh->autoflush();
print $tee purdydate() . " 0x00 Starting SPaste $ver\n";
print $tee purdydate() . " 0x00 Binding to: $host:$port\n";
if (!-w $pasteroot) {
  print $tee purdydate()
    . " 0x0B The paste root directory is not writable! Check permissions!\n";
  exit $SIG{TERM};
}
if (!-r $certfile) {
  print $tee purdydate()
    . " 0x0C The certificate file is not readable! Check permissions!\n";
  exit $SIG{TERM};
}
if (!-r $keyfile) {
  print $tee purdydate()
    . " 0x0D The private key file is not readable! Check permissions!\n";
  exit $SIG{TERM};
}
if (!isint($port)) {
  print $tee purdydate() . " 0x0D The port doesn't seem to be an integer!\n";
  exit $SIG{TERM};
}
if (!isint($seclvl)) {
  print $tee purydate()
    . " 0x0E The security level doesn't seem to be an integer!\n";
  exit $SIG{TERM};
}
if ($seclvl < 8) {
  print $tee prudydate()
    . " 0x0F You cannot set the seclvl lower than 8! It is insecure and could cause collisions!\n";
  exit $SIG{TERM};
}
if ($seclvl < 12) {
  print $tee purdydate()
    . " 0x0F Warning: Setting the security level lower than 12 is probably a bad idea... continuing anyway...\n";
}
my $siteroot = $pasteroot;
$siteroot =~ s|/p/$||;
print $tee purdydate() . " 0x00 Using security level: $seclvl\n";
chdir "$siteroot"
  or die purdydate() . " 0x0A Could not switch to paste root directory! $!";
my $sock = IO::Socket::IP->new(
  Listen    => SOMAXCONN,
  LocalPort => $port,
  Blocking  => 1,
  ReuseAddr => 1)
  or print LOG "0x08 Error: " . prudydate() . " $!";
umask(022); # set umask for created files as 755
my $WITH_THREADS = 1;  # enable threading

while (1) {
  eval {
    my $cl = $sock->accept();    # threaded accept
    if ($cl) {
      my $th = threads->create(\&server, $cl)
        or print $tee purdydate() . " 0x06 Error: Could not create thread! $!";
      $th->detach()
        or print $tee purdydate()
        . " 0x05 Error: Thread detach request failed. $!\n";
    }
  };    # eval
  if ($@) { # forever eval catch
    print $tee purdydate() . " 0x04 Error: No eval! $!\n";
    exit $SIG{TERM};
  }
}    # forever
close(LOG);
close(STDERR);

sub server {
  my $cl = shift; # client socket

  # upgrade INET socket to SSL
  $cl = IO::Socket::SSL->start_SSL(
    $cl,
    SSL_server          => 1,
    SSL_cert_file       => $certfile,
    SSL_key_file        => $keyfile,
    SSL_verifycn_name   => $host,     # verify against host
    SSL_verifycn_scheme => 'default', # protocol scheme
    SSL_hostname        => $host) 
    or do {
    print $tee purdydate() . " 0x01 Error: Could not open socket as SSL! $! ";
    die;
    };

  # unblock
  my $flags = fcntl($cl, F_GETFL, 0)
    or print $tee purdydate() . " 0x09 $cl->peerhost $!";
  my $rndid    = genuniq();
  my $filename = $pasteroot . $rndid;
  print $tee purdydate() . " 0x00 " . $cl->peerhost . "/" . $cl->peerport;
  print $tee " $rndid : storing at $pasteroot$rndid\n";
  print $tee purdydate() . " 0x00 " . $cl->peerhost . "/" . $cl->peerport;
  print $tee " $rndid : serving at $srvname/p/$rndid\n";
  print $cl "$srvname/p/$rndid\n"; # send the client the URL of their paste
  open(P, '>', $filename) or do {
    print $cl "0x0C Error: Could not generate file!";
    print $tee purdydate() . "0x0C Could not write to file! ";
    die;
  };
  while (my $line = $cl->getline()) {    # i can make getline work like this
    print P $line;
  }

  close(P);
  # needs to be closed out way out here to avoid cutting document short
  $cl->close();
  return 0;
}

sub genuniq {
  my $pasid;    # for unique paste identifier
  my @set = ('A' .. 'Z', 'a' .. 'z', 0 .. 9); # character set
  # 26 upper + 26 lower + 10 digits = 62 characters
  # 62 characters in set by 12 is around 18.3T permutations
  # this should be cyrptographically secure enough for our
  # purposes.
  $pasid .= $set[rand($#set)] for 1 .. $seclvl;
  return $pasid;    # push it back
}

sub purdydate {
  my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) =
    localtime(time); # get local time
  my $datetime = sprintf(
    "%04d%02d%02d %02d:%02d:%02d",
    $year + 1900,
    $mon + 1, $mday, $hour, $min, $sec); # format the time
  return $datetime;
}

END {
  if ($cfgf) {
    if (-e $pidfile) {
      unless ($SIG{TERM} || $SIG{INT}) {
        print $tee purdydate()
          . " 0x02 Error: Something unusual happened... check $logfile\n";
      }
      unless ((!-e $logfile) || (!-e $pidfile)) { # cleanup
        print $tee purdydate() . " 0x0B Removing lockfile...\n";
        unlink($pidfile);
      }
    }
    print $tee purdydate() . " 0x00 Stopping SPaste process cleanly...\n";
  }
  else {
    print STDERR
      "0x03 Error: Something unusual happened before config was read... exiting!\n";
  }
}

sub isint {
  my $n = shift;
  return $n =~ /^\s*[+-]?\d+\s*$/;  # check for integer with regex
}


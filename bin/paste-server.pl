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

# -------------------------------------------------------------------------
# Module imports
# -------------------------------------------------------------------------
use strict;
use warnings;
use IO::Handle;                                # for autoflush on filehandles
use Fcntl ("F_GETFL", "F_SETFL", "O_NONBLOCK"); # fcntl constants for non-blocking I/O
use Socket;                                    # low-level socket support
use IO::Socket::SSL;                           # SSL/TLS socket layer
use IO::Socket::SSL::Utils qw(PEM_file2cert CERT_asHash CERT_free); # certificate introspection
use Net::SSLeay qw(load_error_strings ERR_get_error ERR_error_string); # low-level SSL for keypair checks
use threads;                                   # POSIX threads for handling clients concurrently
use IO::Tee;                                   # tee output to multiple filehandles at once
use Config::Tiny;                              # lightweight .ini-style config file parser
use Getopt::Long qw (GetOptions);              # command-line option parsing

# -------------------------------------------------------------------------
# Signal handling and output setup
# -------------------------------------------------------------------------

# Treat SIGTERM and SIGINT (Ctrl-C) as fatal so the END block runs for cleanup
$SIG{TERM} = $SIG{INT} = sub {die "Caught a sigterm $!"};

# Flush STDOUT and STDERR immediately so log lines appear in real time
STDOUT->autoflush();
STDERR->autoflush();

# -------------------------------------------------------------------------
# Basic argument validation before anything else
# -------------------------------------------------------------------------

# Exactly two arguments are required: --conf <file>
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

# -------------------------------------------------------------------------
# Configuration loading
# -------------------------------------------------------------------------

# Declare all config-derived variables up front
my (
  $logfile,  $pasteroot, $host,    $srvname, $port,
  $certfile, $keyfile,   $pidfile, $seclvl,  $maxpastesize);

my $cfgf = undef;
GetOptions('conf=s' => \$cfgf);           # parse --conf <file> into $cfgf
my $config = Config::Tiny->read($cfgf);   # parse the INI-style config file

# Pull each setting out of the parsed config object
$host      = $config->{Server}{fqdn};        # fully-qualified domain name we listen on
$srvname   = $config->{Server}{baseuri};     # base HTTPS URI shown to users in paste links
$port      = $config->{Server}{listenport};  # TCP port to accept incoming paste connections
$certfile  = $config->{SSL}{certfile};       # path to the PEM certificate file
$keyfile   = $config->{SSL}{keyfile};        # path to the PEM private key file
$pidfile   = $config->{Settings}{pidfile};   # lock file written with our PID to prevent double-starts
$pasteroot = $config->{Server}{pasteroot};   # filesystem directory where paste files are stored
$logfile   = $config->{Settings}{logfile};   # log file path
$seclvl    = $config->{Settings}{seclvl};    # number of random characters in a paste ID (entropy level)
$maxpastesize = $config->{Server}{maxpastesize};  # maximum allowed paste size in bytes
my $ver = "v1.3.1";                          # hell yea, new revision!
                                             # can we have a party
                                             # with lots of hookers?
                                             # bonus points for anal beads

# -------------------------------------------------------------------------
# Pre-flight sanity checks
# -------------------------------------------------------------------------

# Prevent starting a second instance by checking for an existing PID file
if (-e $pidfile) {
  die
"0x07 Error: SPaste is already running or the lockfile didn't get wiped!  If you are sure it is not running, remove $pidfile";
}

# Warn loudly if someone accidentally configured a plain-HTTP base URI
if ($srvname =~ m|http:|) {
  print STDERR
"0x09 Error: The baseuri should not be http! Only use a properly configured https server with a fqdn here!\n";
}

# -------------------------------------------------------------------------
# PID file and logging setup
# -------------------------------------------------------------------------

# Write our process ID to the lock file so other tools can find or kill us
open(PIDF, ">", $pidfile) or die $!;
print PIDF $$ . "\n";
close(PIDF);

# Open the log file in append mode and tee all output to both log and STDOUT
open(my $lfh, '>>', $logfile) or die $!;
my $tee = IO::Tee->new($lfh, \*STDOUT);  # writes go to log file AND console
select $tee;                              # make $tee the default output handle
$lfh->autoflush();                        # flush log writes immediately

print $tee purdydate() . " 0x00 Starting SPaste $ver\n";
print $tee purdydate() . " 0x00 Binding to: $host:$port\n";

# Verify the paste storage directory is writable before we try to save anything
if (!-w $pasteroot) {
  print $tee purdydate()
    . " 0x0B The paste root directory is not writable! Check permissions!\n";
  exit $SIG{TERM};
}

# Verify the SSL certificate and key files are readable before binding
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

# Inspect the SSL certificate for validity and expiry before binding
check_ssl_cert($certfile);

# Verify the private key is valid and matches the certificate
check_ssl_keypair($certfile, $keyfile);

# Validate that the port and security level are integers
if (!isint($port)) {
  print $tee purdydate() . " 0x0D The port doesn't seem to be an integer!\n";
  exit $SIG{TERM};
}
if (!isint($seclvl)) {
  print $tee purydate()
    . " 0x0E The security level doesn't seem to be an integer!\n";
  exit $SIG{TERM};
}

# Enforce a minimum security level to prevent trivially short IDs / collisions
if ($seclvl < 8) {
  print $tee prudydate()
    . " 0x0F You cannot set the seclvl lower than 8! It is insecure and could cause collisions!\n";
  exit $SIG{TERM};
}
if ($seclvl < 12) {
  print $tee purdydate()
    . " 0x0F Warning: Setting the security level lower than 12 is probably a bad idea... continuing anyway...\n";
}

# Validate that maxpastesize is a positive integer if provided
if (defined $maxpastesize) {
  if (!isint($maxpastesize) || $maxpastesize <= 0) {
    print $tee purdydate()
      . " 0x0E The maxpastesize doesn't seem to be a positive integer!\n";
    exit $SIG{TERM};
  }
  print $tee purdydate() . " 0x00 Max paste size: $maxpastesize bytes\n";
}

# -------------------------------------------------------------------------
# Server socket setup
# -------------------------------------------------------------------------

# Derive the web root from pasteroot by stripping the trailing "/p/" segment
my $siteroot = $pasteroot;
$siteroot =~ s|/p/$||;

print $tee purdydate() . " 0x00 Using security level: $seclvl\n";

# Change into the site root so relative file operations work correctly
chdir "$siteroot"
  or die purdydate() . " 0x0A Could not switch to paste root directory! $!";

# Create a plain TCP listening socket; SSL is negotiated per-connection in the thread
my $sock = IO::Socket::IP->new(
  Listen    => SOMAXCONN,  # maximum OS backlog of pending connections
  LocalPort => $port,
  Blocking  => 1,
  ReuseAddr => 1)          # allow quick restarts without "address already in use"
  or print LOG "0x08 Error: " . prudydate() . " $!";

umask(022); # set umask so created paste files get mode 644 (world-readable)
my $WITH_THREADS = 1;  # enable threading

# -------------------------------------------------------------------------
# Main accept loop — runs forever, one thread per incoming connection
# -------------------------------------------------------------------------

while (1) {
  eval {
    my $cl = $sock->accept();    # block until a client connects
    if ($cl) {
      # Spin up a new thread to handle this client so the main loop can keep accepting
      my $th = threads->create(\&server, $cl)
        or print $tee purdydate() . " 0x06 Error: Could not create thread! $!";
      # Detach the thread so it cleans itself up when done (no join needed)
      $th->detach()
        or print $tee purdydate()
        . " 0x05 Error: Thread detach request failed. $!\n";
    }
  };    # wrap in eval so a thread error doesn't kill the whole server
  if ($@) { # if eval caught an exception, log it and exit
    print $tee purdydate() . " 0x04 Error: No eval! $!\n";
    exit $SIG{TERM};
  }
}    # loop forever
close(LOG);
close(STDERR);

# -------------------------------------------------------------------------
# server(\$client_socket) — handles a single paste connection in its own thread
# -------------------------------------------------------------------------
sub server {
  my $cl = shift; # raw TCP client socket passed from the accept loop

  # Upgrade the plain TCP socket to SSL/TLS using our certificate and key.
  # This must happen before any data is exchanged with the client.
  $cl = IO::Socket::SSL->start_SSL(
    $cl,
    SSL_server          => 1,
    SSL_cert_file       => $certfile,
    SSL_key_file        => $keyfile,
    SSL_verifycn_name   => $host,     # hostname to verify in the certificate
    SSL_verifycn_scheme => 'default', # use the default verification scheme
    SSL_hostname        => $host)     # SNI hostname sent during handshake
    or do {
    print $tee purdydate() . " 0x01 Error: Could not open socket as SSL! $! ";
    die;
    };

  # Read (but don't change) the current socket flags; used to confirm the fd is valid
  my $flags = fcntl($cl, F_GETFL, 0)
    or print $tee purdydate() . " 0x09 $cl->peerhost $!";

  # Generate a unique, random ID for this paste and build the full storage path
  my $rndid    = genuniq();
  my $filename = $pasteroot . $rndid;

  # Log where the paste will be saved and what URL the client will receive
  print $tee purdydate() . " 0x00 " . $cl->peerhost . "/" . $cl->peerport;
  print $tee " $rndid : storing at $pasteroot$rndid\n";
  print $tee purdydate() . " 0x00 " . $cl->peerhost . "/" . $cl->peerport;
  print $tee " $rndid : serving at $srvname/p/$rndid\n";

  # Immediately send the client the URL where their paste will be accessible
  print $cl "$srvname/p/$rndid\n";

  # Open the paste file for writing; die on failure so the thread exits cleanly
  open(P, '>', $filename) or do {
    print $cl "0x0C Error: Could not generate file!";
    print $tee purdydate() . "0x0C Could not write to file! ";
    die;
  };

  # Read all lines from the client and write them directly to the paste file.
  # getline() blocks until data arrives and returns undef on EOF (client disconnect).
  my $total_bytes = 0;
  while (my $line = $cl->getline()) {
    $total_bytes += length($line);
    if (defined $maxpastesize && $total_bytes > $maxpastesize) {
      close(P);
      unlink($filename);
      print $cl "\r\n\r\n0x0E Error: Paste exceeds maximum allowed size of $maxpastesize bytes!\n";
      print $tee purdydate() . " 0x0E " . $cl->peerhost . " paste too large ($total_bytes bytes), rejected.\n";
      $cl->close();
      return 0;
    }
    print P $line;
  }

  close(P);            # flush and close the paste file
  $cl->close();        # close SSL connection only after the file is fully written
                       # (closing earlier would truncate the paste)
  return 0;
}

# -------------------------------------------------------------------------
# genuniq() — generates a unique paste identifier
# -------------------------------------------------------------------------
sub genuniq {
  my $pasid;    # accumulator for the paste ID string
  my @set = ('A' .. 'Z', 'a' .. 'z', 0 .. 9); # character pool: 26+26+10 = 62 chars
  # With 62 characters and a length of $seclvl (default 12),
  # there are ~3.2 quadrillion possible IDs, which is more than enough
  # to avoid collisions while remaining cryptographically unpredictable.
  $pasid .= $set[rand($#set)] for 1 .. $seclvl; # append one random char per iteration
  return $pasid;
}

# -------------------------------------------------------------------------
# purdydate() — returns the current local time as a formatted timestamp string
# -------------------------------------------------------------------------
sub purdydate {
  # localtime() returns a 9-element list; we only need the first six fields
  my ($sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst) =
    localtime(time);
  # Format as "YYYYMMDD HH:MM:SS" — $year is years-since-1900, $mon is 0-based
  my $datetime = sprintf(
    "%04d%02d%02d %02d:%02d:%02d",
    $year + 1900,
    $mon + 1, $mday, $hour, $min, $sec);
  return $datetime;
}

# -------------------------------------------------------------------------
# END block — Perl calls this automatically when the process is about to exit,
# whether that's due to a signal, a die(), or normal program flow.
# We use it to remove the PID lock file and print a clean shutdown message.
# -------------------------------------------------------------------------
END {
  if ($cfgf) {          # only run cleanup if the config was successfully read
    if (-e $pidfile) {
      unless ($SIG{TERM} || $SIG{INT}) {
        # If we're here without a handled signal, something unexpected happened
        print $tee purdydate()
          . " 0x02 Error: Something unusual happened... check $logfile\n";
      }
      unless ((!-e $logfile) || (!-e $pidfile)) {
        # Remove the lock file so the server can be restarted cleanly
        print $tee purdydate() . " 0x0B Removing lockfile...\n";
        unlink($pidfile);
      }
    }
    print $tee purdydate() . " 0x00 Stopping SPaste process cleanly...\n";
  }
  else {
    # Config was never read, so $tee may not exist — fall back to STDERR
    print STDERR
      "0x03 Error: Something unusual happened before config was read... exiting!\n";
  }
}

# -------------------------------------------------------------------------
# check_ssl_keypair($certfile, $keyfile) — verifies the private key is valid
# and that it forms a matching pair with the certificate.
# Exits with an error if the key is unparseable or does not match the cert.
# -------------------------------------------------------------------------
sub check_ssl_keypair {
  my ($cert_file, $key_file) = @_;

  Net::SSLeay::load_error_strings();
  Net::SSLeay::SSLeay_add_ssl_algorithms();

  # Create a temporary SSL context to load and validate the keypair
  my $ctx = Net::SSLeay::CTX_new();
  if (!$ctx) {
    print $tee purdydate()
      . " 0x0D Error: Could not create SSL context for keypair check.\n";
    exit $SIG{TERM};
  }

  # Attempt to load the certificate into the context
  if (!Net::SSLeay::CTX_use_certificate_file($ctx, $cert_file,
      Net::SSLeay::FILETYPE_PEM()))
  {
    my $err = Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
    print $tee purdydate()
      . " 0x0C Error: Could not load certificate for keypair validation: $err\n";
    Net::SSLeay::CTX_free($ctx);
    exit $SIG{TERM};
  }

  # Attempt to load the private key into the context — catches corrupt/invalid keys
  if (!Net::SSLeay::CTX_use_PrivateKey_file($ctx, $key_file,
      Net::SSLeay::FILETYPE_PEM()))
  {
    my $err = Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
    print $tee purdydate()
      . " 0x0D Error: Private key is invalid or could not be loaded: $err\n";
    Net::SSLeay::CTX_free($ctx);
    exit $SIG{TERM};
  }

  # Verify the private key corresponds to the certificate's public key
  if (!Net::SSLeay::CTX_check_private_key($ctx)) {
    my $err = Net::SSLeay::ERR_error_string(Net::SSLeay::ERR_get_error());
    print $tee purdydate()
      . " 0x0D Error: Private key does not match the certificate: $err\n";
    Net::SSLeay::CTX_free($ctx);
    exit $SIG{TERM};
  }

  Net::SSLeay::CTX_free($ctx);
  print $tee purdydate()
    . " 0x00 SSL certificate and private key pair verified successfully.\n";
}

# -------------------------------------------------------------------------
# check_ssl_cert($certfile) — inspects the PEM certificate for validity/expiry
# Logs a warning (and exits) if the certificate is invalid or already expired.
# Logs a warning (but continues) if it expires within 30 days.
# -------------------------------------------------------------------------
sub check_ssl_cert {
  my ($file) = @_;
  my $cert = eval { PEM_file2cert($file) };
  if ($@ || !$cert) {
    print $tee purdydate()
      . " 0x0C Error: Could not parse SSL certificate file '$file': $@\n";
    exit $SIG{TERM};
  }

  my $info     = CERT_asHash($cert);
  CERT_free($cert);

  my $now        = time();
  my $not_before = $info->{not_before};  # epoch seconds
  my $not_after  = $info->{not_after};   # epoch seconds

  if (!defined $not_before || !defined $not_after) {
    print $tee purdydate()
      . " 0x0C Warning: Could not read validity dates from SSL certificate.\n";
    return;
  }

  if ($now < $not_before) {
    # Certificate is not yet valid
    my $valid_from = scalar localtime($not_before);
    print $tee purdydate()
      . " 0x0C Error: SSL certificate is not yet valid (valid from: $valid_from). Exiting.\n";
    exit $SIG{TERM};
  }

  if ($now > $not_after) {
    # Certificate has already expired
    my $expired_on = scalar localtime($not_after);
    print $tee purdydate()
      . " 0x0C Error: SSL certificate has EXPIRED (expired: $expired_on)."
      . " Clients will receive SSL errors. Exiting.\n";
    exit $SIG{TERM};
  }

  my $days_left = int(($not_after - $now) / 86400);
  if ($days_left <= 30) {
    my $expires_on = scalar localtime($not_after);
    print $tee purdydate()
      . " 0x0C Warning: SSL certificate expires in $days_left day(s) ($expires_on)."
      . " Please renew soon.\n";
  }
  else {
    print $tee purdydate()
      . " 0x00 SSL certificate is valid. Expires in $days_left day(s).\n";
  }
}

# -------------------------------------------------------------------------
# isint($n) — returns true if $n looks like an integer, false otherwise
# -------------------------------------------------------------------------
sub isint {
  my $n = shift;
  return $n =~ /^\s*[+-]?\d+\s*$/;  # allow optional leading/trailing whitespace and sign
}


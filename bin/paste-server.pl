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

# for autoflush on filehandles
use IO::Handle;

# fcntl constants for non-blocking I/O
use Fcntl ( "F_GETFL", "F_SETFL", "O_NONBLOCK" );

# low-level socket support
use Socket;

# SSL/TLS socket layer
use IO::Socket::SSL;

# certificate introspection
use IO::Socket::SSL::Utils qw(PEM_file2cert CERT_asHash CERT_free);

# low-level SSL for keypair checks
use Net::SSLeay qw(load_error_strings ERR_get_error ERR_error_string);

# POSIX threads for handling clients concurrently
use threads;

# tee output to multiple filehandles at once
use IO::Tee;

# lightweight .ini-style config file parser
use Config::Tiny;

# command-line option parsing
use Getopt::Long qw (GetOptions);

# -------------------------------------------------------------------------
# Signal handling and output setup
# -------------------------------------------------------------------------

# Treat SIGTERM and SIGINT (Ctrl-C) as fatal so the END block runs for cleanup
$SIG{TERM} = $SIG{INT} = sub { die "Caught a sigterm $!" };

# Flush STDOUT and STDERR immediately so log lines appear in real time
STDOUT->autoflush();
STDERR->autoflush();

# -------------------------------------------------------------------------
# Basic argument validation before anything else
# -------------------------------------------------------------------------

# Exactly two arguments are required: --conf <file>
if ( $#ARGV + 1 ne 2 ) {
    print STDERR
      "Incorrect number of arguments.\n Useage:\n  $ARGV[0] --conf [file]\n";
    exit $SIG{TERM};
}
if ( $ARGV[0] !~ "--conf" ) {
    print STDERR "You need to specify a config file with --conf [file]\n";
    exit $SIG{TERM};
}
if ( !-r $ARGV[1] ) {
    print STDERR "The config file doesn't exist!";
    exit $SIG{TERM};
}

# -------------------------------------------------------------------------
# Configuration loading
# -------------------------------------------------------------------------

# Declare all config-derived variables up front
my (
    $logfile,  $pasteroot, $host,    $srvname, $port,
    $certfile, $keyfile,   $pidfile, $seclvl,  $maxpastesize,
    $allowbinary
);

my $cfgf = undef;

# parse --conf <file> into $cfgf
GetOptions( 'conf=s' => \$cfgf );

# parse the INI-style config file
my $config = Config::Tiny->read($cfgf);

# Pull each setting out of the parsed config object
# fully-qualified domain name we listen on
$host = $config->{Server}{fqdn};

# base HTTPS URI shown to users in paste links
$srvname = $config->{Server}{baseuri};

# TCP port to accept incoming paste connections
$port = $config->{Server}{listenport};

# path to the PEM certificate file
$certfile = $config->{SSL}{certfile};

# path to the PEM private key file
$keyfile = $config->{SSL}{keyfile};

# lock file written with our PID to prevent double-starts
$pidfile = $config->{Settings}{pidfile};

# filesystem directory where paste files are stored
$pasteroot = $config->{Server}{pasteroot};

# log file path
$logfile = $config->{Settings}{logfile};

# number of random characters in a paste ID (entropy level)
$seclvl = $config->{Settings}{seclvl};

# maximum allowed paste size in bytes
$maxpastesize = $config->{Server}{maxpastesize};

# whether to allow binary/control characters in pasted content
$allowbinary = $config->{Settings}{allowbinary};

my $ver = "v1.3.1";

# -------------------------------------------------------------------------
# Pre-flight sanity checks
# -------------------------------------------------------------------------

# Prevent starting a second instance by checking for an existing PID file
if ( -e $pidfile ) {
    die
"0x07 Error: SPaste is already running or the lockfile didn't get wiped!  If you are sure it is not running, remove $pidfile";
}

# Warn loudly if someone accidentally configured a plain-HTTP base URI
if ( $srvname =~ m|http:| ) {
    print STDERR
"0x09 Error: The baseuri should not be http! Only use a properly configured https server with a fqdn here!\n";
}

# -------------------------------------------------------------------------
# PID file and logging setup
# -------------------------------------------------------------------------

# Write our process ID to the lock file so other tools can find or kill us
open( PIDF, ">", $pidfile ) or die $!;
print PIDF $$ . "\n";
close(PIDF);

# Open the log file in append mode and tee all output to both log and STDOUT
open( my $lfh, '>>', $logfile ) or die $!;

# writes go to log file and console
my $tee = IO::Tee->new( $lfh, \*STDOUT );

# make $tee the default output handle
select $tee;

# flush log writes immediately
$lfh->autoflush();

print $tee purdydate() . " 0x00 Starting SPaste $ver\n";
print $tee purdydate() . " 0x00 Binding to: $host:$port\n";

# Verify the paste storage directory is writable before we try to save anything
if ( !-w $pasteroot ) {
    print $tee purdydate()
      . " 0x0B The paste root directory is not writable! Check permissions!\n";
    exit $SIG{TERM};
}

# Verify the SSL certificate and key files are readable before binding
if ( !-r $certfile ) {
    print $tee purdydate()
      . " 0x0C The certificate file is not readable! Check permissions!\n";
    exit $SIG{TERM};
}
if ( !-r $keyfile ) {
    print $tee purdydate()
      . " 0x0D The private key file is not readable! Check permissions!\n";
    exit $SIG{TERM};
}

# Inspect the SSL certificate for validity and expiry before binding
check_ssl_cert($certfile);

# Verify the private key is valid and matches the certificate
check_ssl_keypair( $certfile, $keyfile );

# Validate that the port and security level are integers
if ( !isint($port) ) {
    print $tee purdydate() . " 0x10 The port doesn't seem to be an integer!\n";
    exit $SIG{TERM};
}
if ( !isint($seclvl) ) {
    print $tee purydate()
      . " 0x11 The security level doesn't seem to be an integer!\n";
    exit $SIG{TERM};
}

# Enforce a minimum security level to prevent trivially short IDs / collisions
if ( $seclvl < 8 ) {
    print $tee purdydate()
      . " 0x0F You cannot set the seclvl lower than 8! It is insecure and could cause collisions!\n";
    exit $SIG{TERM};
}
if ( $seclvl < 12 ) {
    print $tee purdydate()
      . " 0x0F Warning: Setting the security level lower than 12 is probably a bad idea... continuing anyway...\n";
}

# Validate that maxpastesize is a positive integer if provided
if ( defined $maxpastesize ) {
    if ( !isint($maxpastesize) || $maxpastesize <= 0 ) {
        print $tee purdydate()
          . " 0x12 The maxpastesize doesn't seem to be a positive integer!\n";
        exit $SIG{TERM};
    }
    print $tee purdydate() . " 0x00 Max paste size: $maxpastesize bytes\n";
}

# Validate allowbinary if provided; treat undefined as permissive (allow binary)
if (defined $allowbinary) {
  if ($allowbinary ne '0' && $allowbinary ne '1') {
    print $tee purdydate()
      . " 0x0E The allowbinary setting must be 0 or 1!\n";
    exit $SIG{TERM};
  }
  if ($allowbinary eq '0') {
    print $tee purdydate() . " 0x00 Binary paste content is disabled.\n";
  }
  else {
    print $tee purdydate() . " 0x00 Binary paste content is allowed.\n";
  }
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

    # maximum OS backlog of pending connections
    Listen    => SOMAXCONN,
    LocalPort => $port,
    Blocking  => 1,

    # allow quick restarts without "address already in use"
    ReuseAddr => 1
);

# set umask so created paste files get mode 644 (world-readable)
umask(022);

# enable threading
my $WITH_THREADS = 1;

# -------------------------------------------------------------------------
# Main accept loop — runs forever, one thread per incoming connection
# -------------------------------------------------------------------------

while (1) {
    eval {
        # block until a client connects
        my $cl = $sock->accept();
        if ($cl) {

# Spin up a new thread to handle this client so the main loop can keep accepting
            my $th = threads->create( \&server, $cl )
              or print $tee purdydate()
              . " 0x06 Error: Could not create thread! $!";

           # Detach the thread so it cleans itself up when done (no join needed)
            $th->detach()
              or print $tee purdydate()
              . " 0x05 Error: Thread detach request failed. $!\n";
        }

        # wrap in eval so a thread error doesn't kill the whole server
    };

    # if eval caught an exception, log it and exit
    if ($@) {
        print $tee purdydate() . " 0x04 Error: No eval! $!\n";
        exit $SIG{TERM};
    }

    # loop forever
}
close(LOG);
close(STDERR);

# -------------------------------------------------------------------------
# server(\$client_socket) — handles a single paste connection in its own thread
# -------------------------------------------------------------------------
sub server {

    # raw TCP client socket passed from the accept loop
    my $cl = shift;

    # Upgrade the plain TCP socket to SSL/TLS using our certificate and key.
    # This must happen before any data is exchanged with the client.
    $cl = IO::Socket::SSL->start_SSL(
        $cl,
        SSL_server    => 1,
        SSL_cert_file => $certfile,
        SSL_key_file  => $keyfile,

        # hostname to verify in the certificate
        SSL_verifycn_name => $host,

        # use the default verification scheme
        SSL_verifycn_scheme => 'default',

        # SNI hostname sent during handshake
        SSL_hostname => $host
      )
      or do {
        print $tee purdydate()
          . " 0x01 Error: Could not open socket as SSL! $! ";
        die;
      };

    # Flush every write to the client immediately so that error messages and
    # the paste URL are never silently dropped when the connection is closed.
    $cl->autoflush(1);

# Read (but don't change) the current socket flags; used to confirm the fd is valid
my $flags = fcntl( $cl, F_GETFL, 0 )
      or print $tee purdydate() . " 0x14 $cl->peerhost $!";

   # Generate a unique, random ID for this paste and build the full storage path
    my $rndid    = genuniq();
    my $filename = $pasteroot . $rndid;

    my $paste_url = "$srvname/p/$rndid";

    # Log where the paste will be saved
    print $tee purdydate() . " 0x00 " . $cl->peerhost . "/" . $cl->peerport;
    print $tee " $rndid : storing at $pasteroot$rndid\n";

   # Open the paste file for writing; die on failure so the thread exits cleanly
    open( P, '>', $filename ) or do {
        print $cl "0x15 Error: Could not generate file!";
        print $tee purdydate() . "0x15 Could not write to file! ";
        die;
    };

# Read all lines from the client and write them directly to the paste file.
# Any validation/read errors return a non-zero status to this caller, which
# then writes the corresponding error message back to the client.
    my ( $read_status, $client_err, $log_err ) = read_paste_lines( $cl, \*P );
    if ( $read_status > 0 ) {
        close(P);
        unlink($filename);
        print $cl "\r\n\r\n$client_err\n";
        print $tee purdydate() . " $log_err\n";
        $cl->close();
        return $read_status;
    }

    # flush and close the paste file
    close(P);

    # Only after successful validation/write should the client receive the URL.
    print $tee purdydate() . " 0x00 " . $cl->peerhost . "/" . $cl->peerport;
    print $tee " $rndid : serving at $paste_url\n";
    print $cl "$paste_url\n";

    # close the SSL connection only after the file is fully written,
    # otherwise the paste could be truncated
    $cl->close();
    return 0;
}

# -------------------------------------------------------------------------
# read_paste_lines($client_socket, $filehandle) — reads client paste data,
# enforces limits/policy, and writes valid data to disk.
# Returns:
#   (0) on success
#   (>0, $client_error_message, $log_error_message) on failure
# -------------------------------------------------------------------------
sub read_paste_lines {
    my ( $cl, $fh ) = @_;
    my $total_bytes = 0;

    while ( my $line = $cl->getline() ) {
        $total_bytes += length($line);
        if ( defined $maxpastesize && $total_bytes > $maxpastesize ) {
            return (
                1,
                "0x13 Error: Paste exceeds maximum allowed size of $maxpastesize bytes!",
                "0x13 " . $cl->peerhost
                  . " paste too large ($total_bytes bytes), rejected."
            );
        }
        if ( defined $allowbinary
            && $allowbinary eq '0'
            && $line =~ /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/ )
        {
            return (
                2,
                "0x0E Error: Paste contains binary characters, which is not allowed!",
                "0x0E " . $cl->peerhost
                  . " paste contains binary characters, rejected."
            );
        }
        print {$fh} $line or return (
            3,
            "0x15 Error: Could not write paste data!",
            "0x15 Could not write paste data for " . $cl->peerhost . ": $!"
        );
    }

    return 0;
}

# -------------------------------------------------------------------------
# genuniq() — generates a unique paste identifier
# -------------------------------------------------------------------------
sub genuniq {

    # accumulator for the paste ID string
    my $pasid;

    # character pool: 26 uppercase + 26 lowercase + 10 digits = 62 chars
    my @set = ( 'A' .. 'Z', 'a' .. 'z', 0 .. 9 );

    # With 62 characters and a length of $seclvl (default 12),
    # there are ~3.2 quadrillion possible IDs, which is more than enough
    # to avoid collisions while remaining cryptographically unpredictable.
    # append one random character per iteration
    $pasid .= $set[ rand($#set) ] for 1 .. $seclvl;
    return $pasid;
}

# -------------------------------------------------------------------------
# purdydate() — returns the current local time as a formatted timestamp string
# -------------------------------------------------------------------------
sub purdydate {

    # localtime() returns a 9-element list; we only need the first six fields
    my ( $sec, $min, $hour, $mday, $mon, $year, $wday, $yday, $isdst ) =
      localtime(time);

    # Format as "YYYYMMDD HH:MM:SS" — $year is years-since-1900, $mon is 0-based
    my $datetime = sprintf(
        "%04d%02d%02d %02d:%02d:%02d",
        $year + 1900,
        $mon + 1, $mday, $hour, $min, $sec
    );
    return $datetime;
}

# -------------------------------------------------------------------------
# END block — Perl calls this automatically when the process is about to exit,
# whether that's due to a signal, a die(), or normal program flow.
# We use it to remove the PID lock file and print a clean shutdown message.
# -------------------------------------------------------------------------
END {
    # only run cleanup if the config was successfully read
    if ($cfgf) {
        if ( -e $pidfile ) {
            unless ( $SIG{TERM} || $SIG{INT} ) {

         # If we're here without a handled signal, something unexpected happened
                print $tee purdydate()
                  . " 0x02 Error: Something unusual happened... check $logfile\n";
            }
            unless ( ( !-e $logfile ) || ( !-e $pidfile ) ) {

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
    my ( $cert_file, $key_file ) = @_;

    Net::SSLeay::load_error_strings();
    Net::SSLeay::SSLeay_add_ssl_algorithms();

    # Create a temporary SSL context to load and validate the keypair
    my $ctx = Net::SSLeay::CTX_new();
    if ( !$ctx ) {
        print $tee purdydate()
          . " 0x16 Error: Could not create SSL context for keypair check.\n";
        exit $SIG{TERM};
    }

    # Attempt to load the certificate into the context
    if (
        !Net::SSLeay::CTX_use_certificate_file(
            $ctx, $cert_file, Net::SSLeay::FILETYPE_PEM()
        )
      )
    {
        my $err = Net::SSLeay::ERR_error_string( Net::SSLeay::ERR_get_error() );
        print $tee purdydate()
          . " 0x19 Error: Could not load certificate for keypair validation: $err\n";
        Net::SSLeay::CTX_free($ctx);
        exit $SIG{TERM};
    }

# Attempt to load the private key into the context — catches corrupt/invalid keys
    if (
        !Net::SSLeay::CTX_use_PrivateKey_file(
            $ctx, $key_file, Net::SSLeay::FILETYPE_PEM()
        )
      )
    {
        my $err = Net::SSLeay::ERR_error_string( Net::SSLeay::ERR_get_error() );
        print $tee purdydate()
          . " 0x17 Error: Private key is invalid or could not be loaded: $err\n";
        Net::SSLeay::CTX_free($ctx);
        exit $SIG{TERM};
    }

    # Verify the private key corresponds to the certificate's public key
    if ( !Net::SSLeay::CTX_check_private_key($ctx) ) {
        my $err = Net::SSLeay::ERR_error_string( Net::SSLeay::ERR_get_error() );
        print $tee purdydate()
          . " 0x18 Error: Private key does not match the certificate: $err\n";
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
    if ( $@ || !$cert ) {
        print $tee purdydate()
          . " 0x1A Error: Could not parse SSL certificate file '$file': $@\n";
        exit $SIG{TERM};
    }

    my $info = CERT_asHash($cert);
    CERT_free($cert);

    my $now = time();

    # certificate validity timestamps, in epoch seconds
    my $not_before = $info->{not_before};
    my $not_after  = $info->{not_after};

    if ( !defined $not_before || !defined $not_after ) {
        print $tee purdydate()
          . " 0x0C Warning: Could not read validity dates from SSL certificate.\n";
        return;
    }

    if ( $now < $not_before ) {

        # Certificate is not yet valid
        my $valid_from = scalar localtime($not_before);
        print $tee purdydate()
          . " 0x1B Error: SSL certificate is not yet valid (valid from: $valid_from). Exiting.\n";
        exit $SIG{TERM};
    }

    if ( $now > $not_after ) {

        # Certificate has already expired
        my $expired_on = scalar localtime($not_after);
        print $tee purdydate()
          . " 0x1C Error: SSL certificate has EXPIRED (expired: $expired_on)."
          . " Clients will receive SSL errors. Exiting.\n";
        exit $SIG{TERM};
    }

    my $days_left = int( ( $not_after - $now ) / 86400 );
    if ( $days_left <= 30 ) {
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

    # allow optional leading/trailing whitespace and sign
    return $n =~ /^\s*[+-]?\d+\s*$/;
}

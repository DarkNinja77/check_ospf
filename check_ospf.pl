#!/usr/bin/perl
# Filename : check_ospf.pl
# Date     : 2022-03-24

use warnings;
use strict;
use Net::SNMP;
use Getopt::Long;
use Switch;

# ============================================================================
# ============================== NAGIOS VARIABLES ============================
# ============================================================================

my $TIMEOUT      = 15;  # This is the global script timeout, not the SNMP timeout
my %ERRORS       = ('OK'=>0,'WARNING'=>1,'CRITICAL'=>2,'UNKNOWN'=>3,'DEPENDENT'=>4);

# ============================================================================
# ============================== OID VARIABLES ===============================
# ============================================================================

# SNMP OID to OSPF neighbor state table
my $OID_ospfNbrState = "1.3.6.1.2.1.14.10.1.6";
# SNMP numeric states decoded
my %ospfNbrState = ( 1 => 'down',
                     2 => 'attempt',
                     3 => 'init',
                     4 => 'twoWay',
                     5 => 'exchangeStart',
                     6 => 'exchange',
                     7 => 'loading',
                     8 => 'full');

# ============================================================================
# ============================== GLOBAL VARIABLES ============================
# ============================================================================

my $Version     = '1.0';  # Version number of this script
my $o_host      = undef;  # Hostname
my $o_community = undef;  # Community
my $o_port      = 161;    # Port
my $o_help      = undef;  # Want some help ?
my $o_verb      = undef;  # Verbose mode
my $o_version   = undef;  # Print version
my $o_timeout   = undef;  # Timeout (Default 5)
my $o_version1  = undef;  # Use SNMPv1
my $o_version2  = undef;  # Use SNMPv2c
my $o_domain    = undef;  # Use IPv6
my $o_login     = undef;  # Login for SNMPv3
my $o_passwd    = undef;  # Pass for SNMPv3
my $v3protocols = undef;  # V3 protocol list.
my $o_authproto = 'sha';  # Auth protocol
my $o_privproto = 'aes';  # Priv protocol
my $o_privpass  = undef;  # priv password

# ============================================================================
# ============================== SUBROUTINES (FUNCTIONS) =====================
# ============================================================================

# Subroutine: Print version
sub p_version { 
  print "$0 version : $Version\n"; 
}

# Subroutine: Print Usage
sub print_usage {
    print "Usage: $0 [-v] [-6] -H <host> ([-2] -C <snmp_community> | -l login -x passwd [-X pass -L <authp>,<privp>]) [-p <port>] [-t <timeout>] [-V]\n";
}

# Subroutine: Check number
sub isnnum { # Return true if arg is not a number
  my $num = shift;
  if ( $num =~ /^(\d+\.?\d*)|(^\.\d+)$/ ) { return 0 ;}
  return 1;
}

# Subroutine: Print complete help
sub help {
  print "\nSNMP OSPF check for Nagios\nVersion: ",$Version,"\n\n";
  print_usage();
  print <<EOT;

Options:
-v, --verbose
   Print extra debugging information 
-h, --help
   Print this help message
-H, --hostname=HOST
   Hostname or IPv4/IPv6 address of host to check
-6, --use-ipv6
   Use IPv6 connection
-C, --community=COMMUNITY NAME
   Community name for the host's SNMP agent
-1, --v1
   Use SNMPv1
-2, --v2c
   Use SNMPv2c (default)
-l, --login=LOGIN ; -x, --passwd=PASSWD
   Login and auth password for SNMPv3 authentication 
   If no priv password exists, implies AuthNoPriv 
-X, --privpass=PASSWD
   Priv password for SNMPv3 (AuthPriv protocol)
-L, --protocols=<authproto>,<privproto>
   <authproto> : Authentication protocol (md5|sha : default sha)
   <privproto> : Priv protocole (des|aes : default aes) 
-p, --port=PORT
   SNMP port (Default 161)
-t, --timeout=INTEGER
   Timeout for SNMP in seconds (Default: 5)
-V, --version
   Prints version number

EOT
}

# Subroutine: Verbose output
sub verb { 
  my $t=shift; 
  print $t,"\n" if defined($o_verb); 
}

# Subroutine: Verbose output
sub check_options {
  Getopt::Long::Configure ("bundling");
  GetOptions(
    'v'   => \$o_verb,          'verbose'       => \$o_verb,
    'h'   => \$o_help,          'help'          => \$o_help,
    'H:s' => \$o_host,          'hostname:s'    => \$o_host,
    'p:i' => \$o_port,          'port:i'        => \$o_port,
    'C:s' => \$o_community,     'community:s'   => \$o_community,
    'l:s' => \$o_login,         'login:s'       => \$o_login,
    'x:s' => \$o_passwd,        'passwd:s'      => \$o_passwd,
    'X:s' => \$o_privpass,      'privpass:s'    => \$o_privpass,
    'L:s' => \$v3protocols,     'protocols:s'   => \$v3protocols,   
    't:i' => \$o_timeout,       'timeout:i'     => \$o_timeout,
    'V'   => \$o_version,       'version'       => \$o_version,
    '6'   => \$o_domain,        'use-ipv6'      => \$o_domain,
    '1'   => \$o_version1,      'v1'            => \$o_version1,
    '2'   => \$o_version2,      'v2c'           => \$o_version2,
  );


  # Basic checks
  if (defined($o_timeout) && (isnnum($o_timeout) || ($o_timeout < 2) || ($o_timeout > 60))) { 
    print "Timeout must be >1 and <60 !\n";
    print_usage();
    exit $ERRORS{"UNKNOWN"};
  }
  if (!defined($o_timeout)) {
    $o_timeout=5;
  }
  if (defined ($o_help) ) {
    help();
    exit $ERRORS{"UNKNOWN"};
  }

  if (defined($o_version)) { 
    p_version(); 
    exit $ERRORS{"UNKNOWN"};
  }

  # check host and filter 
  if ( ! defined($o_host) ) {
    print_usage();
    exit $ERRORS{"UNKNOWN"};
  }

  # Use IPv6 or IPv4?
  if (defined ($o_domain)) {
    $o_domain="udp/ipv6";
  } else {
    $o_domain="udp/ipv4";
  }

  # Check SNMP information
  if ( !defined($o_community) && (!defined($o_login) || !defined($o_passwd)) ){ 
    print "Put SNMP login info!\n"; 
    print_usage(); 
    exit $ERRORS{"UNKNOWN"};
  }
  if ((defined($o_login) || defined($o_passwd)) && (defined($o_community) || defined($o_version2)) ){ 
    print "Can't mix SNMP v1,v2c,v3 protocols!\n"; 
    print_usage(); 
    exit $ERRORS{"UNKNOWN"};
  }

  # Check SNMPv3 information
  if (defined ($v3protocols)) {
    if (!defined($o_login)) { 
      print "Put SNMP V3 login info with protocols!\n"; 
      print_usage(); 
      exit $ERRORS{"UNKNOWN"};
    }
    my @v3proto=split(/,/,$v3protocols);
    if ((defined ($v3proto[0])) && ($v3proto[0] ne "")) {
      $o_authproto=$v3proto[0];
    }
    if (defined ($v3proto[1])) {
      $o_privproto=$v3proto[1];
    }
    if ((defined ($v3proto[1])) && (!defined($o_privpass))) {
      print "Put SNMP v3 priv login info with priv protocols!\n";
      print_usage(); 
      exit $ERRORS{"UNKNOWN"};
    }
  }
}


# ============================================================================
# ============================== MAIN ========================================
# ============================================================================

check_options();

# Check gobal timeout if SNMP screws up
if (defined($TIMEOUT)) {
  verb("Alarm at ".$TIMEOUT." + ".$o_timeout);
  alarm($TIMEOUT+$o_timeout);
} else {
  verb("no global timeout defined : ".$o_timeout." + 15");
  alarm ($o_timeout+15);
}

# Report when the script gets "stuck" in a loop or takes to long
$SIG{'ALRM'} = sub {
  print "UNKNOWN: Script timed out\n";
  exit $ERRORS{"UNKNOWN"};
};

# Connect to host
my ($session,$error);
if (defined($o_login) && defined($o_passwd)) {
  # SNMPv3 login
  verb("SNMPv3 login");
  if (!defined ($o_privpass)) {
    # SNMPv3 login (Without encryption)
    verb("SNMPv3 AuthNoPriv login : $o_login, $o_authproto");
    ($session, $error) = Net::SNMP->session(
    -domain    => $o_domain,
    -hostname  => $o_host,
    -version  => 3,
    -username  => $o_login,
    -authpassword  => $o_passwd,
    -authprotocol  => $o_authproto,
    -timeout  => $o_timeout
  );  
  } else {
    # SNMPv3 login (With encryption)
    verb("SNMPv3 AuthPriv login : $o_login, $o_authproto, $o_privproto");
    ($session, $error) = Net::SNMP->session(
    -domain    => $o_domain,
    -hostname  => $o_host,
    -version  => 3,
    -username  => $o_login,
    -authpassword  => $o_passwd,
    -authprotocol  => $o_authproto,
    -privpassword  => $o_privpass,
    -privprotocol  => $o_privproto,
    -timeout  => $o_timeout
    );
  }
} else {
  if ((defined ($o_version2)) || (!defined ($o_version1))) {
    # SNMPv2 login
    verb("SNMP v2c login");
    ($session, $error) = Net::SNMP->session(
    -domain    => $o_domain,
    -hostname  => $o_host,
    -version  => 2,
    -community  => $o_community,
    -port    => $o_port,
    -timeout  => $o_timeout
    );
  } else {
    # SNMPv1 login
    verb("SNMP v1 login");
    ($session, $error) = Net::SNMP->session(
    -domain    => $o_domain,
    -hostname  => $o_host,
    -version  => 1,
    -community  => $o_community,
    -port    => $o_port,
    -timeout  => $o_timeout
    );
  }
}

# Check if there are any problems with the session
if (!defined($session)) {
  printf("ERROR opening session: %s.\n", $error);
  exit $ERRORS{"UNKNOWN"};
}

my $exit_val=undef;

# ============================================================================
# ============================== CHECK SNMP OSPF =============================
# ============================================================================

my $output = "";
my $final_status = 0;
my %ospfState;
my $count_OK = 0;
my $count_WARN = 0;
my $count_CRIT = 0;
my $count_UNKN = 0;


# Get SNMP OSPF neighbor state table
my $result = $session->get_table($OID_ospfNbrState);

if (!defined $result) {
   printf "ERROR: %s\n", $session->error();
   $session->close();
   exit $ERRORS{"UNKNOWN"};
}

# Clear the SNMP Transport Domain and any errors associated with the object.
$session->close;

for my $oid (keys $result) {
  verb ("$oid = $result->{$oid}");
  my $ip = $oid;
  $ip =~ s/^$OID_ospfNbrState\.//;
  $ip =~ s/\.0$//;
  $ospfState{$ip} = $result->{$oid};
}

foreach my $neighbor (keys %ospfState) {
  my $state = $ospfState{$neighbor};
  switch($state) {
    case [4,8] {
      $final_status = 0;
      $count_OK++;
    }
    case [2,3,5,6,7] {
      $final_status = 1 if ($final_status < 1);
      $count_WARN++;
    }
    case [1] {
      $final_status = 2 if ($final_status < 2);
      $count_CRIT++;
    }
    else {
      $final_status = 3 if ($final_status < 3);
      $count_UNKN++;
    }
  }
  $output .= "$neighbor\t$ospfNbrState{$state}\n";
}

my $status = "";
$status .= "1 neighbor CRITICAL, " if ($count_CRIT == 1);
$status .= "1 neighbor WARNING, " if ($count_WARN == 1);
$status .= "1 neighbor OK, " if ($count_OK == 1);
$status .= "1 neighbor UNKNOWN, " if ($count_UNKN == 1);
$status .= "$count_CRIT neighbors CRITICAL, " if ($count_CRIT > 1);
$status .= "$count_WARN neighbors WARNING, " if ($count_WARN > 1);
$status .= "$count_OK neighbors OK, " if ($count_OK > 1);
$status .= "$count_UNKN neighbors UNKNOWN, " if ($count_UNKN > 1);
if ($status ne "") {
  chop $status;
  chop $status;
  $status = ": $status.";
}

if ($final_status == 3) {
  print "UNKNOWN",$status,"\n",$output;
  exit $ERRORS{"UNKNOWN"};
}
  
if ($final_status == 2) {
  print "CRITICAL",$status,"\n",$output;
  exit $ERRORS{"CRITICAL"};
}

if ($final_status == 1) {
  print "WARNING",$status,"\n",$output;
  exit $ERRORS{"WARNING"};
}

print "OK",$status,"\n",$output;
exit $ERRORS{"OK"};

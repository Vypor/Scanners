#!/usr/bin/perl
#Requires Net::Pcap, Net::Pcap::Easy and Net::DNS
use threads;
use threads::shared;
use Net::Pcap;
use Net::Pcap::Easy;
use IO::Socket;
use Net::DNS;
use Socket;

if ( $#ARGV != 4 ) {
    print "Usage: dnsscan.pl <ip_start> <ip_end> <minbytereply> <outputfile> <domain>\n";
	print "	Example: dnsscan.pl 67.0.0.0 68.0.0.0 3000 output.txt krebsonsecurity.com\n";
    print "	Coded by Vypor, https://github.com/Vypor\n";
    print "	v.0.1 Dns Scanner\n";
    exit(1);
}

my $thr1       = threads->new( \&LISTEN );
my $thr2       = threads->new( \&SCAN );
my @ReturnData = $thr1->join;
my @ReturnData = $thr2->join;

sub LISTEN {

    my $interface = pcap_lookupdev( \$err );    # find a device
    my $leastsize = $ARGV[2];
    my $LOGFILE   = $ARGV[3];
    my $domain    = $ARGV[4];
    my $ethip = `/sbin/ifconfig $interface | grep "inet addr" | awk -F: '{print \$2}' | awk '{print \$1}'`;
    $ethip = substr( $ethip, 0, -1 );

    my $listener = Net::Pcap::Easy->new(
        dev => $interface,
        filter =>
          "port 53 and udp and not src host $ethip and greater $leastsize",
        packets_per_loop => 10,
        bytes_to_capture => 0,
        timeout_in_ms    => 0,
        promiscuous      => 0,

        udp_callback => sub {
            my ( $listener, $ether, $ip, $udp, $header ) = @_;
            open( FILE, ">>$LOGFILE" );
            print FILE "$ip->{src_ip} $domain $udp->{len}\n";
            close FILE;
            print "$ip->{src_ip} $domain $udp->{len}\n";
        }
    );
    1 while $listener->loop;

}

sub SCAN {

    my $start  = $ARGV[0];
    my $end    = $ARGV[1];
    my $domain = $ARGV[4];

    #Make The Packet
    my $dnspacket = new Net::DNS::Packet( $domain, 'IN', 'ANY' );
    $dnspacket->header->qr(0);    #Query Responce Flag
    $dnspacket->header->aa(0);    #Authoritative Flag
    $dnspacket->header->tc(0);    #Truncated Flag
    $dnspacket->header->ra(0);    #Recursion Desired
    $dnspacket->header->rd(1);    #Recursion Available
    $udp_max = $dnspacket->header->size(65527);    #Max Allowed Byte Size
    my $dnsdata = $dnspacket->data;

    my $start_address  = unpack 'N', inet_aton($start);
    my $finish_address = unpack 'N', inet_aton($end);

    for my $address ( $start_address .. $finish_address ) {
        my $str = sprintf inet_ntoa( pack 'N', $address );

        my $socket = IO::Socket::INET->new(
            Proto    => 'udp',
            PeerPort => 53,
            SockPort => 53,
            PeerAddr => $str,
        ) or die "Could not create socket: $!\n";

        $socket->send($dnsdata) or die "Send Error: $!\n";
    }

}

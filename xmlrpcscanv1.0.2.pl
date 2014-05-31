use strict;
use threads;
use threads::shared;
use Thread::Queue;
use IO::Socket;

if ( $#ARGV != 3 ) {
    print "Usage: wpscan.pl <iplist> <folderlist> <threads> <output>\n";
    print "Coded by Vypor, https://github.com/Vypor\n";
    print "v.0.2, wordpress exploit scanner\n";
    exit(1);
}

my $iplist        = $ARGV[0];
my $directorylist = $ARGV[1];
our $MAX //= $ARGV[2];
my $logfile = $ARGV[3];

my $foundwp : shared = 0;
my $donewp : shared  = 0;

local $| = 1;

open( FILE, $iplist );
my @lines = <FILE>;
close(FILE);
my $totalwp = @lines;

open my $directorys, '<', $directorylist;
chomp( my @directorys = <$directorys> );
close $directorys;

print "Starting Scan...\n";
print "IP list: $iplist\n";
print "Directory List: $directorylist\n";
print "Log File: $logfile\n";
print "Threads: $MAX\n";
print "Loading Threads...\n\n";

my $Q = new Thread::Queue;

sub thread {
    while ( my $ip = $Q->dequeue ) {

        foreach (@directorys) {
            my $socket = IO::Socket::INET->new(
                Proto    => 'tcp',
                PeerAddr => $ip,
                PeerPort => '80',
                Timeout  => '3',
            ) or return $!;
	            my $doneurl = "http://" . $ip . "/" . $_ . "/xmlrpc.php";
            	
	    print $socket "GET /" . $_ . "xmlrpc.php HTTP/1.0\r\n";
            print $socket "Host: ", $ip, "\r\n";
            print $socket "Connection: close", "\r\n";
            print $socket "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)", "\r\n";
            print $socket "Accept: text/html, application/xhtml+xml, */*", "\r\n\r\n";

            my @array = <$socket>;
            my $pagetext = join( '', @array );
            if ( $pagetext =~ /XML-RPC/ ) {
				
	    my $socket2 = IO::Socket::INET->new(
                Proto    => 'tcp',
                PeerAddr => $ip,
                PeerPort => '80',
                Timeout  => '3',
	            ) or return $!;
            my $ui = "http://" . $ip . "/" . $_ . "/?feed=rss2";
            print $socket2 "GET /" . $_ . "/?feed=rss2 HTTP/1.0\r\n";
            print $socket2 "Host: ", $ip, "\r\n";
            print $socket2 "Connection: close", "\r\n";
            print $socket2 "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)", "\r\n";
            print $socket2 "Accept: text/html, application/xhtml+xml, */*", "\r\n\r\n";
						
						            my @array2 = <$socket2>;
						my $pagetext2 = join( '', @array2 );
                        					$pagetext2 =~ /<item>.+?<link>(.+?)<\/link>.+?<\/item>/s;
                        if ($1) {
                               					 open (FILE, ">>$logfile");
								my $post = $1;
								$ui =~ s{\Q?feed=rss2\E}{xmlrpc.php};
								print FILE "$ui $post\n";                                
				                                close (FILE);
								print "Found: $foundwp | Total: $donewp/$totalwp\r";
									                lock($foundwp);
												$foundwp++;
												last;
                        }
						
						
						

               # print "Found: $foundwp | Total: $donewp/$totalwp\r";
               # open( LOGFILE, ">>$logfile" );
               ## print LOGFILE "$doneurl\n";
               # close(LOGFILE);
                
            }
            else {
                print "Found: $foundwp | Total: $donewp/$totalwp\r";
            }
            lock($donewp);
            $donewp++;
        }

    }
}

my @threads = map async( \&thread ), 1 .. $MAX;

open my $handle, '<', $iplist;
chomp, $Q->enqueue($_) while defined( $_ = <$handle> );
close $handle;

$Q->enqueue( (undef) x $MAX );
$_->join for @threads;

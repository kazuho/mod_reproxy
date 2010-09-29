use strict;
use warnings;

use LWP::Simple qw(get);
use t::Test qw(run_tests);
use Test::More;
use Test::TCP;

my $test = t::Test->new(
    required_modules => [ qw(cgi mime reproxy) ],
    custom_conf => << "EOT",
DocumentRoot t/assets
AddHandler cgi-script .cgi
Reproxy On
EOT
);

test_tcp(
    server => sub {
        my $port = shift;
        my $listen_sock = IO::Socket::INET->new(
            Listen    => 5,
            LocalAddr => '127.0.0.1',
            LocalPort => $port,
            Proto     => 'tcp',
        ) or die "failed to listen:$!";
        while (my $sock = $listen_sock->accept) {
            $sock->sysread(my $buf, 1048576);
            $sock->syswrite(
                join(
                    "",
                    "HTTP/1.0 200 OK\r\n",
                    "Content-Type: text/plain\r\n",
                    "Content-Length: 5\r\n",
                    "\r\n",
                    "hello world",
                ),
            );
            $sock->close();
        }
    },
    client => sub {
        my $port = shift;
        is(
            get("http://@{[$t::Test::httpd->listen]}/reproxy.cgi?url="
                    . "http://127.0.0.1:$port/"),
            "hello",
            "only receive # of bytes specified in content-length header",
        );
    },
);

done_testing;

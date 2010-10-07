use strict;
use warnings;

use Plack::Builder;
use Plack::Middleware::Static;
use Digest::MD5 qw(md5_hex);
use LWP::UserAgent;
use t::Test;
use Test::More;
use Test::TCP;

test_tcp(
    server => sub {
        my $port = shift;
        Plack::Loader->auto(
            host => '127.0.0.1',
            port => $port,
        )->run(
            Plack::Middleware::Static->new(
                path => sub { 1 },
                root => 't/assets',
            ),
        );
    },
    client => sub {
        my $port = shift;
        my $test = t::Test->new(
            required_modules => [ qw(cgi mime reproxy) ],
            custom_conf => << "EOT",
DocumentRoot t/assets
AddHandler cgi-script .cgi
AddType image/jpeg .jpg
Reproxy On
EOT
        );
        
        # the tests
        my $ua = LWP::UserAgent->new();
        my $r = $ua->get(
            "http://@{[$t::Test::httpd->listen]}/reproxy.cgi?url="
                . "http://127.0.0.1:$port/bozuman.jpg",
        );
        is $r->code, 200, 'status code';
        is length($r->content), 603189, 'size';
        is md5_hex($r->content), 'faf76c34a08839becf5059550a8df404', 'content';
    },
);

done_testing;


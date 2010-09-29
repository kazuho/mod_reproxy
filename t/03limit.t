use strict;
use warnings;

use Plack::App::CGIBin;
use Plack::Builder;
use t::Test qw(run_tests);
use Test::More;
use Test::TCP;

# setup http server on different port and refer to it thru mod_proxy
test_tcp(
    server => sub {
        my $port = shift;
        Plack::Loader->auto(
            host => '127.0.0.1',
            port => $port,
        )->run(builder {
            mount '/target' => sub {
                return [
                    200,
                    [ 'Content-Type' => 'text/plain' ],
                    [ 'hello' ],
                ];
            };
            mount '/' => Plack::App::CGIBin->new(root => 't/assets')->to_app;
        });
    },
    client => sub {
        my $port = shift;
        my $test = t::Test->new(
            required_modules => [ qw(proxy proxy_http reproxy) ],
            custom_conf      => << "EOT",
<Location />
  ProxyPass http://127.0.0.1:$port/
  ProxyPassReverse http://127.0.0.1:$port/
</Location>
Reproxy On
ReproxyLimitURL ^http://[^/]+/target/allowed/
EOT
        );
        
        # the tests
        my $ua = LWP::UserAgent->new();
        my $r = $ua->get(
            "http://@{[$t::Test::httpd->listen]}/reproxy.cgi?url="
                . "http://127.0.0.1:$port/target/allowed/hoge",
        );
        is $r->code, 200, 'allowed status';
        is $r->content, 'hello', 'allowed content';
        $r = $ua->get(
            "http://@{[$t::Test::httpd->listen]}/reproxy.cgi?url="
                . "http://127.0.0.1:$port/target/not_allowed/hoge",
        );
        is $r->code, 500, 'not-allowed status';
    },
);

done_testing;

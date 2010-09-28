use strict;
use warnings;

use LWP::Simple qw(get);
use LWP::UserAgent;
use Plack::App::CGIBin;
use Plack::Builder;
use t::Test;
use Test::More;
use Test::TCP;

test_tcp(
    server => sub {
        my $port = shift;
        Plack::Loader->auto(
            host => '127.0.0.1',
            port => $port,
        )->run(builder {
            mount '/redirect_once' => sub {
                return [
                    302,
                    [ 'Location', "http://127.0.0.1:$port/destination" ],
                    [ 'redirect_once' ],
                ];
            };
            mount '/destination' => sub {
                return [
                    200,
                    [ 'Content-Type', 'text/plain' ],
                    [ 'destination' ],
                ];
            };
            mount '/redirect_loop' => sub {
                return [
                    302,
                    [ 'Location', "http://127.0.0.1:$port/redirect_loop" ],
                    [ 'loop' ],
                ];
            },
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
EOT
        );
        
        # the tests
        is(
            get("http://@{[$t::Test::httpd->listen]}/reproxy.cgi?url="
                    . "http://127.0.0.1:$port/redirect_once"),
            'destination',
            'simple redirection',
        );
        my $r = LWP::UserAgent->new->get(
            "http://@{[$t::Test::httpd->listen]}/reproxy.cgi?url="
                . "http://127.0.0.1:$port/redirect_loop",
        );
        is $r->code, 500, '500 on infinite loop';
        warn $r->message;
    },
);

done_testing;

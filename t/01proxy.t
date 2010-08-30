use strict;
use warnings;

use Plack::App::CGIBin;
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
        )->run(Plack::App::CGIBin->new(root => 't/assets')->to_app);
    },
    client => sub {
        my $port = shift;
        my $test = t::Test->new(
            required_modules => [ qw(proxy proxy_http reproxy) ],
            custom_conf      => << "EOT",
<Location />
  ProxyPass http://127.0.0.1:$port/
  ProxyPassReverse http://127.0.01:$port/
</Location>
Reproxy On
EOT
        );
        run_tests();
    },
);

done_testing;

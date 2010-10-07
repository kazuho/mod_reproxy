use strict;
use warnings;

use t::Test qw(run_tests);
use Test::More;

my $test = t::Test->new(
    required_modules => [ qw(cgi mime reproxy) ],
    custom_conf => << "EOT",
DocumentRoot t/assets
AddHandler cgi-script .cgi
Reproxy On
TypesConfig /dev/null
EOT
);

run_tests();

done_testing;

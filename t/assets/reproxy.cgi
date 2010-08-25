#! /usr/bin/perl

use strict;
use warnings;

use CGI;

my $query = CGI->new();
my $reproxy_url = $query->param('url') || '';

print << "EOT";
Content-Type: text/plain
X-Reproxy-URL: $reproxy_url

should never see this
EOT

#! /usr/bin/perl

use strict;
use warnings;

use CGI;

my $query = CGI->new();
my $reproxy_url = $query->param('url') || '';
my $mime_type = $query->param('type') || 'text/plain';

print << "EOT";
Content-Type: $mime_type
X-Reproxy-URL: $reproxy_url

should never see this
EOT

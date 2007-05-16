#!/usr/bin/perl -w

use strict;

use Test::More tests => 6;

BEGIN {
    use_ok('Net::Whois::Raw',qw( whois ));

    $Net::Whois::Raw::CHECK_FAIL = 1;
    $Net::Whois::Raw::OMIT_MSG = 1;
    $Net::Whois::Raw::CHECK_EXCEED = 1;
    $Net::Whois::Raw::DEBUG = 1;
};

my @domains = qw( 
    yahoo.com
    freshmeat.net
    freebsd.org
    reg.ru
    ns1.nameself.com.NS
);

print "The following tests requires internet connection...\n";

foreach my $domain ( @domains ) {
    my $txt = whois( $domain );
    $domain =~ s/.NS$//i;
    ok($txt && $txt =~ /$domain/i, "$domain resolved");
}


#!/usr/bin/perl -w

use strict;

use Test::More tests => 6;
BEGIN {
    use_ok('Net::Whois::Raw',qw( whois $CHECK_FAIL $OMIT_MSG $CHECK_EXCEED ));

    $Net::Whois::Raw::CHECK_FAIL = 1;
    $Net::Whois::Raw::OMIT_MSG = 1;
    $Net::Whois::Raw::CHECK_EXCEED = 1;
};

my @domains = qw( 
	yahoo.com
	freshmeat.net
	freebsd.org
	webnames.ru
	ns1.nameself.com.NS
);

print "The following tests requires internet connection...\n";

foreach my $domain ( @domains ) {
	my $txt = whois( $domain );
	$domain =~ s/.NS$//i;
	ok($txt =~ /$domain/i, "$domain resolved");
}


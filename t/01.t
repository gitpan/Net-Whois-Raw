# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

use strict;

use Test::More tests => 2;
BEGIN { use_ok('Net::Whois::Raw') };


my $txt = whois("yahoo.com");

ok($txt =~ /YAHOO.COM/, 'yahoo.com resolved');

#$txt = whois("perl.org.il");
#ok($txt =~ /Gabor Szabo/, 'perl.org.il resolved');


#$txt = whois("atheist.org.il");
#if ($txt =~ /Ariel Brosh/) {

#$txt = whois("147.222.2.1");

#if ($txt =~ /Gonzaga/) {
#    print "ok 4\n";
#} else {
#    print "not ok 4\n";
#}

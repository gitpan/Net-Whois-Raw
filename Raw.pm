package Net::Whois::Raw;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %servers $OMIT_MSG $CHECK_FAIL);

use IO::Socket;

require Exporter;

@ISA = qw(Exporter);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
whois $OMIT_MSG $CHECK_FAIL
);
$VERSION = '0.17';

%servers = qw(COM whois.networksolutions.com
         NET whois.networksolutions.com
         EDU whois.networksolutions.com
         ORG whois.networksolutions.com
         ARPA whois.arin.net
         RIPE whois.ripe.net
         MIL whois.nic.mil
         RU whois.ripn.net
         SU whois.ripn.net
         IL whois.isoc.org.il
         TO whois.tonic.to
	 COOP whois.nic.coop
	 MUSEUM whois.museum
	 DK whois.dk-hostmaster.dk
	 DZ whois.ripe.net
	 GS whois.adamsnames.tc
	 IN whois.ncst.ernet.in
	 KH whois.nic.net.kh
	 MS whois.adamsnames.tc
	 TC whois.adamsnames.tc
	 TF whois.adamsnames.tc
	 TJ whois.nic.tj
	 US whois.isi.edu
	 VG whois.adamsnames.tc
);

sub whois {
    my $tld;
    my $dom = shift;
    my @tokens = split(/\./, $dom);
    if ($dom =~ /\d+\.\d+\.\d+\.\d+/) {
        $tld = "ARPA";
    } else { 
	$tld = uc($tokens[-1]); 
    }
    my $srv = $servers{$tld} || "$tld.whois-servers.net";
    my $flag = ($srv eq 'whois.networksolutions.com' || $tld eq 'ARPA');
    _whois($dom, uc($srv), $flag, [], $tld);
}

sub _whois {
    my ($dom, $srv, $flag, $ary, $tld) = @_;
    my $state;

    my $sock = new IO::Socket::INET("$srv:43") || die $!;
    print $sock "$dom\r\n";
    my @lines = <$sock>;
    close($sock);
    if ($flag) {
        foreach (@lines) {
            $state ||= (/^\s*Registrar:/);
            if ($state && /^\s*Whois Server: ([A-Za-z0-9\-_\.]+)/) {
                my $newsrv = uc("$1");
                next if ($newsrv eq $srv);
                return undef if (grep {$_ eq $newsrv} @$ary);
                return _whois($dom, $newsrv, $flag, [@$ary, $srv]);
            }
            if (/^\s+Maintainer:\s+RIPE\b/ && $tld eq 'ARPA') {
                my $newsrv = uc($servers{'RIPE'});
                next if ($newsrv eq $srv);
                return undef if (grep {$_ eq $newsrv} @$ary);
                return _whois($dom, $newsrv, $flag, [@$ary, $srv]);
            }
        }
    }
    local ($_) = join("", @lines);
    if ($OMIT_MSG) {	
        s/The Data.+(policy|connection)\.\n//is;
        s/% NOTE:.+prohibited\.//is;
        s/Disclaimer:.+\*\*\*\n?//is;
        s/NeuLevel,.+A DOMAIN NAME\.//is;
        s/For information about.+page=spec//is;
        s/NOTICE: Access to.+this policy.//is;
        s/The previous information.+completeness\.//s;
    }
    if ($CHECK_FAIL) {
        return undef if /is unavailable/is ||
	   /No entries found for the selected source/is ||
	   /Not found:/s ||
	   /No match\./s;
    }
    $_;
}


# Preloaded methods go here.

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Net::Whois::Raw - Perl extension for unparsed raw whois information

=head1 SYNOPSIS

  use Net::Whois::Raw;
  
  $s = whois('perl.com');
  $s = whois('funet.fi');
  $s = whois('yahoo.co.uk');

  $OMIT_MSG = 1; # This will attempt to strip several knwon copyright
		messages and disclaimers
  $CHECK_FAIL = 1; # This will return undef if the response matches
		one of the known patterns for a failed search.

=head1 DESCRIPTION

Net::Whois::Raw queries NetworkSolutions and follows the Registrar: answer
for ORG, EDU, COM and NET domains.
For other TLDs it uses the whois-servers.net namespace.
(B<$TLD>.whois-servers.net).

Setting the variables $OMIT_MSG and $CHECK_FAIL will match the results
against a set of known patterns. The first flag will try to omit the
copyright message/disclaimer, the second will attempt to determine if
the search failed and return undef in such a case.

B<IMPORTANT>: these checks merely use pattern matching; they will work
on several servers but certainly not on all of them.

(This features were contributed by Walery Studennikov B<despair@sama.ru>)

=head1 AUTHOR

Ariel Brosh, B<schop@cpan.org>, Inspired by jwhois.pl available on the
net.

Peter Chow, B<peter@interq.or.jp>, Corrections. (See below)

Alex Withers B<awithers@gonzaga.edu>, ARIN support. (See below)

Walery Studennikov B<despair@sama.ru>, several servers and the pattern matching idea.

Philip Hands B<phil@uk.alcove.com>, Trevor Peirce B<trev@digitalcon.ca>,
RIPE reverse lookup support. (See below)

=head1 MODIFICATIONS

=item

Fixed regular expression to match hyphens. (Peter Chow,
B<peter@interq.or.jp>)

=item

Added support for Tonga TLD. (.to) (Peter Chow, B<peter@interq.or.jp>)

=item

Added support for reverse lookup of IP addresses via the ARIN registry. (Alex Withers B<awithers@gonzaga.edu>)
This will work now for RIPE addresses as well, according to a redirection from ARIN.

=head1 CLARIFICATION

As NetworkSolutions got most of the domains of InterNic as legacy, we
start by querying their server, as this way one whois query would be
sufficient for many domains. Starting at whois.internic.net or
whois.crsnic.net will result in always two requests in any case.

=head1 COPYRIGHT

Copyright 2000-2001 Ariel Brosh.

This package is free software. You may redistribute it or modify it under
the same terms as Perl itself.

I apologize for any misunderstandings caused by the lack of a clear
licence in previous versions.

=head1 COMMERCIAL SUPPORT

As of May 2001, commercial support for modules by SCHOP@CPAN is available
via Raz Information Systems, Israel. Mail raz@raz.co.il for
details. Note: this is only for commercial organizations in need of
support contracts. You are not requested to pay anything to use the module
in your organization for a commercial application and there are no
royalties for redistributing it to your customers.

=head1 SEE ALSO

L<perl(1)>, L<Net::Whois>.

=cut

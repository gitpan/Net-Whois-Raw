package Net::Whois::Raw;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %servers $OMIT_MSG $CHECK_FAIL
	%notfound %strip $CACHE_DIR $CACHE_TIME $USE_CNAMES
	$TIMEOUT);
use IO::Socket;

require Exporter;

@ISA = qw(Exporter);

@EXPORT = qw(whois $OMIT_MSG $CHECK_FAIL $CACHE_DIR $CACHE_TIME
	$USE_CNAMES $TIMEOUT);
$VERSION = '0.22';

($OMIT_MSG, $CHECK_FAIL, $CACHE_DIR, $CACHE_TIME,
        $USE_CNAMES, $TIMEOUT) = (0) x 6;

%servers = qw(COM whois.networksolutions.com
         NET whois.networksolutions.com
         EDU whois.networksolutions.com
         ORG whois.networksolutions.com
         ARPA whois.arin.net
         RIPE whois.ripe.net
         MIL whois.nic.mil
	 COOP whois.nic.coop
	 MUSEUM whois.museum
         AD  whois.ripe.net
         AL  whois.ripe.net
         AM  whois.ripe.net
         AS  whois.gdns.net
         AT  whois.nic.at
         AU  box2.aunic.net
         AZ  whois.ripe.net
         BA  whois.ripe.net
         BE  aardvark.dns.be
         BG  whois.ripe.net
         BR  whois.nic.br
         BY  whois.ripe.net
         CA  eider.cira.ca
         CC  whois.nic.cc
         CH  domex.switch.ch
         CK  whois.ck-nic.org.ck
         CL  nic.cl
         CN  log.cnnic.net.cn
         CX  whois.nic.cx
         CY  whois.ripe.net
         CZ  dc1.eunet.cz
         DE  whois.denic.de
         DK  whois.dk-hostmaster.dk
         DO  ns.nic.do
         DZ  whois.ripe.net
         EE  whois.ripe.net
         EG  whois.ripe.net
         ES  whois.ripe.net
         FI  whois.ripe.net
         FO  whois.ripe.net
         FR  winter.nic.fr
         GA  whois.ripe.net
         GB  whois.ripe.net
         GE  whois.ripe.net
         GL  whois.ripe.net
         GM  whois.ripe.net
         GR  whois.ripe.net
         GS  whois.adamsnames.tc
         HK  whois.hkdnr.net.hk
         HR  whois.ripe.net
         HU  whois.nic.hu
         ID  muara.idnic.net.id
         IE  whois.domainregistry.ie
         IL  whois.isoc.org.il
         IN  whois.ncst.ernet.in
         IS  horus.isnic.is
         IT  whois.nic.it
         JO  whois.ripe.net
         JP  whois.nic.ad.jp
         KG  whois.domain.kg
         KH  whois.nic.net.kh
         KR  whois.krnic.net
         LA  whois.nic.la
         LI  domex.switch.ch
         LK  arisen.nic.lk
         LT  ns.litnet.lt
         LU  whois.dns.lu
         LV  whois.ripe.net
         MA  whois.ripe.net
         MC  whois.ripe.net
         MD  whois.ripe.net
         MM  whois.nic.mm
         MS  whois.adamsnames.tc
         MT  whois.ripe.net
         MX  whois.nic.mx
         NL  gw.domain-registry.nl
         NO  ask.norid.no
         NU  whois.worldnames.net
         NZ  akl-iis.domainz.net.nz
         PL  nazgul.nask.waw.pl
         PT  whois.ripe.net
         RO  whois.rotld.ro
         RU  whois.ripn.net
         SE  ear.nic-se.se
         SG  qs.nic.net.sg
         SH  whois.nic.sh
         SI  whois.arnes.si
         SK  whois.ripe.net
         SM  whois.ripe.net
         ST  whois.nic.st
         SU  whois.ripn.net
         TC  whois.adamsnames.tc
         TF  whois.adamsnames.tc
         TH  whois.thnic.net
         TJ  whois.nic.tj
         TN  whois.ripe.net
         TO  whois.tonic.to
         TR  whois.ripe.net
         TW  whois.twnic.net
         UA  whois.net.ua
         UK  whois.nic.uk
         US  whois.isi.edu
         VA  whois.ripe.net
         VG  whois.adamsnames.tc
         WS  whois.worldsite.ws
         YU  whois.ripe.net
         ZA  apies.frd.ac.za
);

# These do not seem to work
#         CN  log.cnnic.net.cn
#         DK  whois.dk-hostmaster.dk
#         US  whois.isi.edu
# These serve only several subdomains
#         ZA  apies.frd.ac.za
sub whois {
    my ($dom, $srv) = @_;
    my $res;
    unless ($srv) {
        ($res, $srv) = query($dom);
    } else {
        $res = _whois($dom ,uc($srv));
    }
    finish($res, $srv);
}

sub query {
    my $dom = shift;
    my $tld;
    my @tokens = split(/\./, $dom);
    if ($dom =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) {
        $tld = "ARPA";
    } else { 
        $tld = uc($tokens[-1]); 
    }
    my $cname = "$tld.whois-servers.net";
    my $srv = $servers{$tld} || $cname;
    $srv = $cname if $USE_CNAMES && gethostbyname($cname); 
    my $flag = ($srv eq 'whois.networksolutions.com' || $tld eq 'ARPA');
    my $res = do_whois($dom, uc($srv), $flag, [], $tld);
    wantarray ? ($res, $srv) : $res;
}

sub do_whois {
    my ($dom) = @_; # receives 4 parameters, do NOT shift
    return _whois(@_) unless $CACHE_DIR;
    mkdir $CACHE_DIR, 0644;
    if (-f "$CACHE_DIR/$dom") {
        if (open(I, "$CACHE_DIR/$dom")) {
            my $res = join("", <I>);
            close(I);
            return $res;
        }
    }
    my $res = _whois(@_);
    return $res unless $res;
    return $res unless open(O, ">$CACHE_DIR/$dom");
    print O $res;
    close(O);


    return $res unless $CACHE_TIME;

    my $now = time;
    foreach (glob("$CACHE_DIR/*.*")) {
        my $atime = (stat($_))[8];
        my $elapsed = $now - $atime;
        unlink $_ if ($elapsed / 3600 > $CACHE_TIME); 
    }
    $res;
}

sub finish {
    my ($text, $srv) = @_;
    return $text unless $CHECK_FAIL || $OMIT_MSG;
    require Net::Whois::Raw::Data;
    *notfound = \%Net::Whois::Raw::Data::notfound;
    *strip = \%Net::Whois::Raw::Data::strip;

    my $notfound = $notfound{lc($srv)};
    my @strip = $strip{lc($srv)} ? @{$strip{lc($srv)}} : ();
    my @lines;
    MAIN: foreach (split(/\n/, $text)) {
        return undef if $CHECK_FAIL && /$notfound/;
        if ($OMIT_MSG) {
            foreach my $re (@strip) {
                next MAIN if (/$re/);
            }
        }
        push(@lines, $_);
    }
    local ($_) = join("\n", @lines, "");

    if ($OMIT_MSG > 1) {	
        s/The Data.+(policy|connection)\.\n//is;
        s/% NOTE:.+prohibited\.//is;
        s/Disclaimer:.+\*\*\*\n?//is;
        s/NeuLevel,.+A DOMAIN NAME\.//is;
        s/For information about.+page=spec//is;
        s/NOTICE: Access to.+this policy.//is;
        s/The previous information.+completeness\.//s;
    }
    if ($CHECK_FAIL > 2) {
        return undef if /is unavailable/is ||
	   /No entries found for the selected source/is ||
	   /Not found:/s ||
	   /No match\./s;
    }
    $_;
}

sub _whois {
    my ($dom, $srv, $flag, $ary, $tld) = @_;
    my $state;

    my $sock;
    eval {
        local $SIG{'ALRM'} = sub { die "Connection timeout to $srv" };
        alarm $TIMEOUT if $TIMEOUT;
        $sock = new IO::Socket::INET("$srv:43") || die $!;
    };
    alarm 0;
    die $@ if $@;
    print $sock "$dom\r\n";
    my @lines = <$sock>;
    close($sock);
    if ($flag) {
        foreach (@lines) {
            $state ||= (/^\s*Registrar:/);
            if ($state && /^\s*Whois Server: ([A-Za-z0-9\-_\.]+)/) {
                my $newsrv = uc("$1");
                next if (($newsrv) eq uc($srv));
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
    join("", @lines);
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

  $OMIT_MSG = 1; # This will attempt to strip several known copyright
		messages and disclaimers sorted by servers.
		Default is to give the whole response.

  $OMIT_MSG = 2; # This will try some additional stripping rules
		if none are known for the spcific server.

  $CHECK_FAIL = 1; # This will return undef if the response matches
		one of the known patterns for a failed search,
		sorted by servers.
		Default is to give the textual response.

  $CHECK_FAIL = 2; # This will match against several more rules
		if none are known for the specific server.

  $CACHE_DIR = "/var/spool/pwhois/"; # Whois information will be
		cached in this directory. Default is no cache.

  $CACHE_TIME = 24; # Cache files will be cleared after not accessed
		for a specific number of hours. Documents will not be
		cleared if they keep get requested for, independent
		of disk space. Default is not to clear the cache.

  $USE_CNAMES = 1; # Use whois-servers.net to get the whois server
		name when possible. Default is to use the 
		hardcoded defaults.


  $TIMEOUT = 10; # Cancel the request if connection is not made within
		a specific number of seconds.

  Note: as of version 0.21, extra data will be loaded only if the
  OMIT_MSG or CHECK_FAIL flags were used, in order to reduce memory usage.

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

Original author Ariel Brosh, B<schop@cpan.org>, 
Inspired by jwhois.pl available on the net.

Since Ariel has passed away in September 2002:

Current maintainer Gabor Szabo, B<gabor@perl.org.il>

=head1 CREDITS

Fixed regular expression to match hyphens. (Peter Chow,
B<peter@interq.or.jp>)

Added support for Tonga TLD. (.to) (Peter Chow, B<peter@interq.or.jp>)

Added support for reverse lookup of IP addresses via the ARIN registry. (Alex Withers B<awithers@gonzaga.edu>)

This will work now for RIPE addresses as well, according to a redirection from ARIN. (Philip Hands B<phil@uk.alcove.com>, Trevor Peirce B<trev@digitalcon.ca>)

Added the pattern matching switches, (Walery Studennikov B<despair@sama.ru>)

Modified pattern matching, added cache. (Tony L. Svanstrom B<tony@svanstrom.org>)

=head1 CHANGES

0.22 2003.01.12
     After Ariel Brosh, the original author has passed away this is the
     first release by Gabor Szabo, the new maintainer.

     It comes mainly to record the change in ownership.

     Tests:
        moving test.pl to t/01.t
        using Test::More
        removing failing tests. Later I'll add more test.


=head1 CLARIFICATION

As NetworkSolutions got most of the domains of InterNic as legacy, we
start by querying their server, as this way one whois query would be
sufficient for many domains. Starting at whois.internic.net or
whois.crsnic.net will result in always two requests in any case.

=head1 NOTE

Some users complained that the B<die> statements in the module make their
CGI scripts crash. Please consult the entries on B<eval> and
B<die> on L<perlfunc> about exception handling in Perl.

=head1 COPYRIGHT

Copyright 2000-2002 Ariel Brosh.
Copyright 2003-2003 Gabor Szabo.

This package is free software. You may redistribute it or modify it under
the same terms as Perl itself.

I apologize for any misunderstandings caused by the lack of a clear
licence in previous versions.

=head1 COMMERCIAL SUPPORT

Not available anymore.

=head1 LEGAL

Notice that registrars forbid querying their whois servers as a part of
a search engine, or querying for a lot of domains by script. 
Also, omitting the copyright information (that was requested by users of this 
module) is forbidden by the registrars.

=head1 SEE ALSO

L<perl(1)>, L<Net::Whois>, L<whois>.

=cut

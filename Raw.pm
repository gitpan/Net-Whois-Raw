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
$VERSION = '0.20';

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

%notfound = (
          'whois.nic.cc.error' => '^No match for',
          'whois.arin.net.error' => '^No match for',
          'whois.nic.br.error' => 'No match for',
          'ear.nic-se.se.error' => 'No data found',
          'whois.nic.sh.error' => '^No match for',
          'whois.nic.mx.error' => '^Nombre del Dominio:',
          'whois.domainregistry.ie.error' => 'There was no match',
          'domex.switch.ch.error' => '^We do not have an entry in our database matching your',
          'whois.dns.lu.error' => 'No entries found',
          'whois.worldsite.ws.error' => 'No match for',
          'whois.nic.it.error' => '^No entries found',
          'whois.nic.coop.error' => 'No Objects Found',
          'whois.nic.at.error' => 'nothing found',
          'ask.norid.no.error' => 'no matches',
          'whois.nic.uk.error' => '^\\s*No match for',
          'whois.nic.ad.jp.error' => 'No match',
          'whois.arnes.si.error' => 'No entries found',
          'whois.tonic.to.error' => 'No match for',
          'whois.hkdnr.net.hk.error' => '^No Match for',
          'whois.worldnames.net.error' => 'NO MATCH for domain',
          'whois.rotld.ro.error' => 'No entries found',
          'whois.nic.st.error' => '^No entries found',
          'whois.isoc.org.il.error' => 'No data was found',
          'eider.cira.ca.error' => 'Status:\\s*UNAV',
          'whois.nic.tj.error' => '^No match for',
          'aardvark.dns.be.error' => 'No such domain',
          'nazgul.nask.waw.pl.error' => '^Domain name .* does not exists',
          'whois.ncst.ernet.in.error' => '^No matches',
          'whois.krnic.net.error' => 'Above domain name is not registered',
          'whois.museum.error' => '^No information for',
          'whois.net.ua.error' => 'No entries found',
          'apies.frd.ac.za.error' => 'No information is available',
          'gw.domain-registry.nl.error' => 'invalid query',
          'whois.denic.de.error' => 'No entries found',
          'whois.nic.mil.error' => '^No match for',
          'horus.isnic.is.error' => 'No entries found',
          'winter.nic.fr.error' => 'No entries found',
          'whois.ripe.net.error' => 'No entries found',
          'whois.ripn.net.error' => 'No entries found',
          'qs.nic.net.sg.error' => 'NO entry found',
          'whois.twnic.net.error' => '^NO MATCH: This domain is',
          'nic.cl.error' => 'Invalid domain name',
          'whois.gdns.net.error' => '^Domain Not Found',
          'box2.aunic.net.error' => 'No entries found',
          'whois.nic.cx.error' => '^No match for',
          'dc1.eunet.cz.error' => 'No data found',
          'akl-iis.domainz.net.nz.error' => 'domain_name_status: 00 Not Listed',
          'ns.litnet.lt.error' => 'No matches found',
          'whois.adamsnames.tc.error' => 'is not a domain controlled by',
          'whois.nic.la.error' => '^NO MATCH for',
          'whois.networksolutions.com.error' => '^No match for',
          'whois.thnic.net.error' => 'No entries found');

%strip = (
          'whois.tonic.to' => [
                                '^Tonic whoisd'
                              ],
          'whois.net.ua' => [
                              '^%'
                            ],
          'whois.nic.cx' => [
                              '^ Registrar: Christmas Island',
                              '^ Whois Server: whois.nic.cx'
                            ],
          'gw.domain-registry.nl' => [
                                       'Rights restricted by copyright',
                                       'http://www.domain-registry.nl'
                                     ],
          'whois.denic.de' => [
                                '^%'
                              ],
          'whois.gdns.net' => [
                                '^\\w+ Whois Server',
                                '^Access to .* WHOIS information is provided to',
                                '^determining the contents of a domain name',
                                '^registrar database.  The data in',
                                '^informational purposes only, and',
                                '^Compilation, repackaging, dissemination,',
                                '^in its entirety, or a substantial portion',
                                'prior written permission.  By',
                                '^by this policy.  All rights reserved.'
                              ],
          'whois.isoc.org.il' => [
                                   '^%'
                                 ],
          'whois.dns.lu' => [
                              '^%'
                            ],
          'whois.worldnames.net' => [
                                      '^----------------------------------',
                                      '^.\\w+ Domain .* Whois service',
                                      '^Copyright by .* Domain LTD',
                                      '^----------------------------------',
                                      '^Database last updated'
                                    ],
          'whois.nic.sh' => [
                              '^NIC Whois Server'
                            ],
          'whois.nic.coop' => [
                                '^%',
                                '^ The .COOP Registration',
                                '^ Please use the'
                              ],
          'domex.switch.ch' => [
                                 '^whois: This information is subject',
                                 '^See http'
                               ],
          'whois.twnic.net' => [
                                 '^Registrar:',
                                 '^URL: http://rs.twnic.net.tw'
                               ],
          'nic.cl' => [
                        '^cl.cl:',
                        '^Más información: http://www.nic.cl/'
                      ],
          'whois.nic.mx' => [
                              '^------------------',
                              '^La información que ha',
                              '^relacionados con la',
                              '^DNS administrado por el NIC-México.',
                              '^Queda absolutamente prohibido',
                              '^envío de e-mail no solicitado',
                              '^productos y servicios',
                              '^del NIC-México.',
                              '^La base de datos generada',
                              '^protegida por las leyes de',
                              '^internacionales sobre la materia.'
                            ],
          'whois.domainregistry.ie' => [
                                         '^%'
                                       ],
          'ns.litnet.lt' => [
                              '^%'
                            ],
          'dc1.eunet.cz' => [
                              '^%'
                            ],
          'whois.ripn.net' => [
                                '^%'
                              ],
          'whois.nic.uk' => [
                              '^The .* Registration Host contains information',
                              '^registrations in the .*co.uk',
                              'and .*\\.uk second-level domains.'
                            ],
          'whois.nic.br' => [
                              '^%'
                            ],
          'whois.krnic.net' => [
                                 '^Korea Internet Information Service',
                                 '^20\\d\\d³â 7¿ù 2ÀÏºÎÅÍ´Â °³¼±µÈ Whois',
                                 '^.com, .net, .org'
                               ],
          'whois.arnes.si' => [
                                '^\\*'
                              ],
          'nazgul.nask.waw.pl' => [
                                    '^%'
                                  ],
          'whois.nic.la' => [
                              '^   WHOIS server',
                              '^   The Data in the',
                              'for information purposes,',
                              '^   and to assist persons in obtaining',
                              '^   domain name registration record. Sterling Holdings, Limited,',
                              '^   does not guarantee its accuracy.',
                              '^   you will use this Data only for lawful',
                              '^   circumstances will you use this Data',
                              '^   \\(1\\) allow, enable, or otherwise s',
                              '^   unsolicited, commercial advertising',
                              '^   \\(spam\\); or',
                              '^   that apply to Sterling Holdings',
                              '^   Sterling Holdings .* reserves the right to modify',
                              '^   terms at any time. By submitting this',
                              '^   policy.'
                            ],
          'horus.isnic.is' => [
                                '^%'
                              ],
          'whois.rotld.ro' => [
                                '^%'
                              ],
          'whois.nic.st' => [
                              '^The data in the .* database is provided',
                              '^The .* Registry does not guarantee',
                              '^The data in the .* database is protected',
                              '^By submitting a .* query, you agree that you will',
                              '^The Domain Council of .* reserves the right'
                            ],
          'ask.norid.no' => [
                              '^%'
                            ],
          'whois.hkdnr.net.hk' => [
                                    '^Whois server',
                                    '^Domain names in the',
                                    '^and .* can now be registered',
                                    '^Go to http://www.hkdnr.net.hk',
                                    '^---------',
                                    '^The Registry contains ONLY',
                                    '^.* and .*\\.HK domains.'
                                  ],
          'whois.arin.net' => [
                                '^The ARIN Registration Services Host contains',
                                '^Network Information:.*Networks',
                                '^Please use the whois server at',
                                '^Information and .* for .* Information.'
                              ],
          'qs.nic.net.sg' => [
                               '^\\*'
                             ],
          'akl-iis.domainz.net.nz' => [
                                        '^%'
                                      ],
          'whois.nic.hu' => [
                              '^%'
                            ],
          'whois.worldsite.ws' => [
                                    '^Welcome to the .* Whois Server',
                                    '^Use of this service for any',
                                    '^than determining the',
                                    '^in the .* to be registered',
                                    '^prohibited.'
                                  ],
          'whois.ripe.net' => [
                                '^%'
                              ],
          'whois.nic.cc' => [
                              '^This information is',
                              '^The Data in eNIC',
                              '^Corporation for information',
                              '^in obtaining information',
                              '^registration record',
                              '^accuracy.  By submitting',
                              '^will use this Data only',
                              '^no circumstances will',
                              '^or otherwise support',
                              '^commercial advertising',
                              '^or \\(2\\) enable high volume',
                              '^apply to eNIC Corporation',
                              '^reserves the right to',
                              '^submitting this query,'
                            ],
          'whois.nic.mil' => [
                               '^To single out one record',
                               '^handle, shown in parenthesis',
                               '^Please be advised that this whois',
                               '^All INTERNET Domain, IP Network Number,',
                               '^the Internet Registry, RS.INTERNIC.NET.'
                             ],
          'box2.aunic.net' => [
                                '^%'
                              ],
          'whois.nic.ad.jp' => [
                                 '^['
                               ],
          'winter.nic.fr' => [
                               '^Tous droits reserves par copyright.',
                               '^Voir http://www.nic.fr',
                               '^Rights restricted by copyright.',
                               '^See http://www.nic.fr/outils'
                             ],
          'ear.nic-se.se' => [
                               '^#'
                             ],
          'whois.networksolutions.com' => [
                                            '^The Data in',
                                            '^Solutions for information',
                                            '^information about or',
                                            '^Network Solutions does not guarantee',
                                            '^WHOIS query, you agree that',
                                            '^purposes and that, under no circumstances',
                                            '^\\(1\\) allow, enable, or',
                                            '^unsolicited, commercial advertising',
                                            '^\\(spam\\); or',
                                            '^that apply to Network',
                                            '^reserves the right',
                                            '^this query, you'
                                          ],
          'aardvark.dns.be' => [
                                 '^%'
                               ],
          'whois.nic.tj' => [
                              '^This Whois server looks up only',
                              '^Please see http://nic.tj for more',
                              '^Tajikistan, and the Public Registrar Network.'
                            ],
          'whois.nic.at' => [
                              '^%'
                            ]
        );

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
    my $notfound = $notfound{lc($srv)};
    my @strip = $strip{lc($srv)} ? @{$strip{lc($srv)}} : ();
    return $text unless $CHECK_FAIL || $OMIT_MSG;
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

=head1 CREDITS

Fixed regular expression to match hyphens. (Peter Chow,
B<peter@interq.or.jp>)

Added support for Tonga TLD. (.to) (Peter Chow, B<peter@interq.or.jp>)

Added support for reverse lookup of IP addresses via the ARIN registry. (Alex Withers B<awithers@gonzaga.edu>)

This will work now for RIPE addresses as well, according to a redirection from ARIN. (Philip Hands B<phil@uk.alcove.com>, Trevor Peirce B<trev@digitalcon.ca>)

Added the pattern matching switches, (Walery Studennikov B<despair@sama.ru>)

Modified pattern matching, added cache. (Tony L. Svanstrom B<tony@svanstrom.org>)

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
royalties for redistributing it to your customers. Also, the copyright is mine
and not of the supporting company.

=head1 SEE ALSO

L<perl(1)>, L<Net::Whois>, L<whois>.

=cut

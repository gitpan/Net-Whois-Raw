package Net::Whois::Raw::Data;

# Use string as is
no utf8;

use strict;

our @www_whois = qw(
    VN
    AC
    BZ
    TJ
);
# Candidates for www_whois: DO, IO, MG, MN, SH, TM, TP, ZA

our %servers = qw(
    RU          whois.ripn.net
    SU          whois.ripn.net
    
    COM.RU	whois.ripn.net
    NET.RU	whois.ripn.net
    ORG.RU	whois.ripn.net
    PP.RU	whois.ripn.net
    SPB.RU	whois.relcom.ru
    MSK.RU	whois.relcom.ru
    RU.NET	whois.relcom.ru
    MSK.SU      whois.relcom.ru
    INT.RU      whois.int.ru    
    NNOV.RU     whois.nnov.ru

    NS     whois.nsiregistry.net
    RIPE   whois.ripe.net
    IP     whois.arin.net

    AERO   whois.aero
    ARPA   whois.arin.net
    ASIA   whois.nic.asia
    BIZ    whois.biz
    CAT    whois.cat
    CC     ccwhois.verisign-grs.com
    COM    whois.crsnic.net
    COOP   whois.nic.coop
    EDU    whois.educause.edu
    GOV    whois.dotgov.gov
    INFO   whois.afilias.net
    INT    whois.iana.org
    JOBS   jobswhois.verisign-grs.com
    MIL    whois.nic.mil
    MOBI   whois.dotmobiregistry.net
    MUSEUM whois.museum
    NAME   whois.nic.name
    NET    whois.crsnic.net
    ORG    whois.pir.org
    PRO    whois.registrypro.pro
    TEL    whois-tel.neustar.biz
    TV     tvwhois.verisign-grs.com
    WS     whois.worldsite.ws

    NF     whois.nic.cx

    AC  whois.nic.ac
    AG  whois.nic.ag
    AM  whois.amnic.net
    AT  whois.nic.at
    AU  whois.aunic.net
    BE  whois.dns.be
    BG  whois.register.bg
    BJ  whois.nic.bj
    BR  whois.registro.br
    CA  whois.cira.ca
    CH  whois.nic.ch
    CI  whois.nic.ci
    CL  Whois.nic.cl
    CN  whois.cnnic.net.cn
    CX  whois.nic.cx
    CZ  whois.nic.cz
    DE  whois.denic.de
    DK  whois.dk-hostmaster.dk
    DM  whois.nic.dm
    EE  whois.eenet.ee
    EU  whois.eu
    FI  whois.ficora.fi
    FR  whois.nic.fr
    GG  whois.channelisles.net
    GI  whois2.afilias-grs.net
    GS  whois.nic.gs
    HU  whois.nic.hu
    HK  whois.hkirc.hk
    HN  whois2.afilias-grs.net
    IE  whois.domainregistry.ie
    IL  whois.isoc.org.il
    IN  whois.inregistry.net
    IO  whois.nic.io
    IS  whois.isnic.is
    IT  whois.nic.it
    JE  whois.channelisles.net
    JP  whois.jprs.jp
    KE  whois.kenic.or.ke
    KR  whois.nic.or.kr
    KZ  whois.nic.kz
    LA  whois2.afilias-grs.net
    LI  whois.nic.li
    LT  whois.domreg.lt
    LU  whois.dns.lu
    LV  whois.nic.lv
    MG  whois.nic.mg
    MN  whois.nic.mn
    MS  whois.nic.ms
    MU  whois.nic.mu
    MX  whois.nic.mx
    MY  whois.mynic.net.my
    NA  whois.na-nic.com.na
    NL  whois.domain-registry.nl
    NO  whois.norid.no
    NU  whois.nic.nu
    NZ  whois.srs.net.nz
    PL  whois.dns.pl
    PM  whois.nic.pm
    PR  whois.nic.pr
    PT  whois.dns.pt
    RE  whois.nic.re
    RO  whois.rotld.ro
    SB  whois.nic.net.sb
    SC  whois2.afilias-grs.net
    SE  whois.iis.se
    SG  whois.nic.net.sg
    SH  whois.nic.sh
    SI  whois.arnes.si
    ST  whois.nic.st
    TC  whois.adamsnames.tc
    TF  whois.nic.tf
    TK  whois.dot.tk
    TL  whois.nic.tl
    TM  whois.nic.tm
    TO  whois.tonic.to
    TR  whois.nic.tr
    TW  whois.twnic.net.tw
    UA  whois.net.ua
    UK  whois.nic.uk
    US  whois.nic.us
    UZ  whois.cctld.uz
    VC  whois2.afilias-grs.net
    VE  whois.nic.ve
    VG  whois.adamsnames.tc
    WF  whois.nic.wf
    YT  whois.nic.yt

    NET.UA      delta.hostmaster.net.ua
    DN.UA       whois.dn.ua
    LG.UA       whois.lg.ua
    OD.UA       whois.od.ua
    AC.UK	whois.ja.net
    GOV.UK	whois.ja.net

    XN---P1AG	ru.whois.i-dns.net
    XN---P1AG	ru.whois.i-dns.net
    XN---J1AEF	whois.i-dns.net
    XN---E1APQ	whois.i-dns.net
    XN---C1AVG	whois.i-dns.net

    EU.COM      whois.centralnic.com
    GB.COM      whois.centralnic.com
    KR.COM	whois.centralnic.com
    US.COM	whois.centralnic.com
    QC.COM	whois.centralnic.com
    DE.COM	whois.centralnic.com
    NO.COM	whois.centralnic.com
    HU.COM	whois.centralnic.com
    JPN.COM	whois.centralnic.com
    UY.COM	whois.centralnic.com
    ZA.COM	whois.centralnic.com
    BR.COM	whois.centralnic.com
    CN.COM	whois.centralnic.com
    SA.COM	whois.centralnic.com
    SE.COM	whois.centralnic.com
    UK.COM      whois.centralnic.com
    RU.COM	whois.centralnic.com

    GB.NET      whois.centralnic.com
    UK.NET      whois.centralnic.com
    SE.NET	whois.centralnic.com

    AE.ORG	whois.centralnic.com
);


our %ip_whois_servers = qw(
    AFRINIC	whois.afrinic.net
    APNIC	whois.apnic.net
    ARIN	whois.arin.net
    LACNIC	whois.lacnic.net
    RIPE	whois.ripe.net

    JPNIC	whois.nic.ad.jp
    KRNIC	whois.krnic.net
);


# for not utf8
our %codepages = (
    'whois.nic.cl'       => 'iso-8859-1',
    'whois.ttpia.com'    => 'iso-8859-1',
    'whois.registro.br'  => 'iso-8859-1',
    'whois.cira.ca'      => 'iso-8859-1',
    'whois.denic.de'     => 'iso-8859-1',
    'whois.eenet.ee'     => 'iso-8859-1',
    'whois.ficora.fi'    => 'iso-8859-1',
    'whois.isnic.is'     => 'iso-8859-1',
    'whois.nic.hu'       => 'iso-8859-1',
    'whois.dns.pt'       => 'iso-8859-1',
    'whois.net.ua'       => 'koi8-u',
    'whois.dn.ua'        => 'koi8-u',
    'whois.lg.ua'        => 'koi8-u',
    'whois.od.ua'        => 'koi8-u',
    'whois.jprs.jp'      => 'iso-2022-jp',
    'whois.nic.or.kr'    => 'euc-kr',
);


our %notfound = (
    'whois.arin.net'        => '^No match found',
    'whois.ripe.net'        => 'No entries found',

    'whois.ripn.net'        => 'No entries found',
    'whois.relcom.ru'       => 'No entries found',
    'whois.nnov.ru'         => 'No entries found',
    'whois.int.ru'          => 'No entries found',
    'whois.reg.ru'          => '^Domain \S+ not found',
    
    'whois.aero'                 => '^NOT FOUND',
    'whois.nic.asia'             => '^NOT FOUND',
    'whois.biz'                  => '^Not found:',
    'whois-tel.neustar.biz'      => '^Not found',
    'whois.cat'		         => '^% Object \S+ NOT FOUND',
    'whois.nic.coop'             => 'No domain records',
    'whois.educause.edu'         => '^No Match',
    'whois.nic.mil'              => '^No match for',
    'whois.museum'               => '^% Object \S+ NOT FOUND',
    'whois.afilias.net'          => '^NOT FOUND',
    'whois.crsnic.net'           => '^No match for',
    'whois.networksolutions.com' => '(?i)no match',
    'whois.dotmobiregistry.net'  => '^NOT FOUND',
    'whois.nic.name'             => '^No match',
    'whois.iana.org'             => '^Domain \S+ not found',
    'whois.pir.org'              => '^NOT FOUND',
    'ccwhois.verisign-grs.com'   => '^No match for',
    'jobswhois.verisign-grs.com' => '^No match for',
    'tvwhois.verisign-grs.com'   => '^No match for',
    'whois.registrypro.pro'      => '^Unknown domain',
    'whois.worldsite.ws'         => 'No match for',

    'whois.nic.ag'            => 'NOT FOUND',
    'whois.nic.at'            => 'nothing found',
    'whois.amnic.net'         => 'No match',
    'whois.aunic.net'         => 'No Data Found',
    'whois.dns.be'            => '^Status:\s+FREE',
    'whois.register.bg'       => '^Domain name \S+ does not exist',
    'whois.registro.br'       => 'No match for',
    'whois.cira.ca'           => '^Domain status\:\s+AVAIL',
    'whois.nic.ch'            => '^We do not have an entry in our database matching your',
    'whois.nic.ci'            => '^Domain \S+ not found',
    'whois.nic.cl'            => '\: no existe',
    'whois.nic.cx'            => 'Status\: Not Registered',
    'whois.nic.cz'            => 'No data found',
    'whois.denic.de'          => 'No entries found',
    'whois.nic.dm'            => 'Status\: Not Registered',
    'whois.dk-hostmaster.dk'  => '^No entries found for',
    'whois.eenet.ee'          => '^NOT FOUND',
    'whois.eu'                => '^Status:\s+AVAILABLE',
    'whois.ficora.fi'         => 'Domain not found',
    'whois.nic.fr'            => 'No entries found',
    'whois.channelisles.net'  => 'No information found',
    'whois.nic.gs'            => 'Status: Not Registered',
    'whois.hkirc.hk'          => '^Domain Not Found',
    'whois.nic.hu'            => 'No match',
    'whois.domainregistry.ie' => 'There was no match',    
    'whois.isoc.org.il'       => 'No data was found',
    'whois.inregistry.net'    => 'NOT FOUND',
    'whois.nic.io'            => 'Domain \S+ - Available',
    'whois.isnic.is'          => 'No entries found',
    'whois.nic.it'            => 'Status:\s+AVAILABLE',
    'whois.jprs.jp'           => 'No match',
    'whois.kenic.or.ke'       => 'No match found',
    'whois.nic.or.kr'         => 'Above domain name is not registered',
    'whois.nic.kz'            => 'Nothing found for this query',
    'whois.nic.li'            => 'We do not have an entry',
    'whois.domreg.lt'         => '^Status:\s+available',
    'whois.dns.lu'            => 'No such domain',
    'whois.nic.lv'            => 'Nothing found',
    'whois.nic.ms'            => 'Status\: Not Registered',
    'whois.nic.mx'            => 'Object_Not_Found',
    'whois.mynic.net.my'      => '^Domain Name \S+ does not',
    'whois.na-nic.com.na'     => '^Status\: Not Registered',
    'whois.domain-registry.nl' => '^\S+ is free',
    'whois.norid.no'          => 'no matches',
    'whois.nic.nu'            => '^NO MATCH for domain',
    'whois.srs.net.nz'        => '^query_status\: (500 Invalid|220 Avail)',
    'whois.dns.pl'            => 'No information about domain',
    'whois.nic.pm'            => 'No entries found',
    'whois.nic.pr'            => 'No records matching',
    'whois.dns.pt'            => 'no match',
    'whois.nic.re'            => 'No entries found',
    'whois.rotld.ro'          => 'No entries found',
    'whois.iis.se'            => '^\S+ not found',
    'whois.nic.net.sg'        => '^Domain Not Found',
    'whois.nic.sh'            => '^Domain \S+ - Available',
    'whois.arnes.si'          => 'No entries found',
    'whois.nic.st'            => '^No entries found',
    'whois.adamsnames.tc'     => '^\S+ is not registered',
    'whois.nic.tl'            => 'Status\: Not Registered',
    'whois.nic.tf'            => 'No entries found',
    'whois.dot.tk'            => 'domain name not known',
    'whois.nic.tm'            => '^Domain \S+ - Available',
    'whois.tonic.to'          => 'No match for',
    'whois.twnic.net.tw'      => '^No Found',    
    'whois.net.ua'            => 'No entries found for domain',
    'delta.hostmaster.net.ua' => 'No entries found for domain',
    'whois.dn.ua'             => 'No match record found',
    'whois.lg.ua'             => 'No match record found',
    'whois.od.ua'             => 'No match record found',
    'whois.nic.uk'            => 'No match for',
    'whois.ja.net'            => '^No such domain',
    'whois.nic.us'            => '^Not found',
    'whois.nic.ve'            => 'No match for',
    'whois.nic.wf'            => 'No entries found',
    'whois.nic.yt'            => 'No entries found', 

    
    'whois.nsiregistry.net'     => 'No match for',

    'whois.007names.com'        => '^The Domain Name \S+ does not exist',
    'whois.0101domain.com'      => 'No match for domain',
    'whois.1stdomain.net'       => '^No domain found',
    'whois.123registration.com' => '^No match for',
     # 'whois.1isi.com'         -- empty on not fount
     # 'whois.35.com'           -- empty on not fount
    'whois.4domains.com'        => 'Domain Not Found', # Answer on first query -- "Please try again in 4 seconds"
    'whois.activeregistrar.com' => '^Domain name not found',
    'whois.addresscreation.com' => '^No match for',
     # 'whois.advantage-interactive.com' -- show empty fields
    'whois2.afilias-grs.net'    => '^NOT FOUND',
    'whois.aitdomains.com'      => '^No match for',
    'whois.alldomains.com'      => '^No match for',
    'whois.centralnic.com'      => '^This domain name may be available for',
    'whois.communigal.net'      => '^NOT FOUND',
    'whois.desertdevil.com'     => 'No match for domain',
    'whois.directi.com'         => 'No Match for',
    'whois.directnic.com'       => '^No match for',
    'whois.domaindiscover.com'  => '^No match for',
    'whois.domainstobeseen.com' => 'No match for',
    'whois.dotregistrar.com'    => '^No match for',
    'whois.dotster.com'         => 'No match for',
    'whois.ename.com'           => 'Out of Registry',
    'whois.enameco.com'         => 'No match for',
    'whois.gandi.net'           => 'Not found',
    'whois.gdns.net'            => '^Domain Not Found',
    'whois.getyername.com'      => '^No match for',
    'whois.godaddy.com'         => '^No match for',
    'whois.joker.com'           => 'object\(s\) not found',
    'whois.markmonitor.com'     => 'No entries found',
    'whois.melbourneit.com'     => '^Invalid/Unsupported whois name check',
    'whois.moniker.com'         => '^No Match',
    'whois.names4ever.com'      => '^No match for',
     # 'whois.namesbeyond.com'  ??? my IP in black list
    'whois.nameisp.com'         => 'domain not found',
     # 'whois.namescout.com'    -- need big timeout
    'whois.namesystem.com'      => '^Sorry, Domain does not exist',
    'whois.nordnet.net'         => 'No match for',
    'whois.paycenter.com.cn'    => 'no data found',
    'whois.pir.net'             => 'NOT FOUND',
    'whois.plisk.com'           => 'No match for',
    'whois.publicdomainregistry.com' => 'No match for',
    'whois.regtime.net'         => 'Domain \S+ not found',
    'whois.schlund.info'        => '^Domain \S+ is not registered here',
    'whois.thnic.net'           => 'No entries found',
    'whois.tucows.com'          => '^Can.t get information on non-local domain',
    'whois.ttpia.com'           => 'No match for',
    'whois.worldnames.net'      => 'NO MATCH for domain',
     # 'whois.yournamemonkey.com' -- need try again
    'whois.cnnic.net.cn'	=> 'no matching record',
    'me.whois-servers.net'	=> 'NOT FOUND',
    
    'www_whois'                 => '(Available|no records found|is free)', # for VN | TJ | TJ zone
);

our %strip = (
    'whois.arin.net' => [
	'^The ARIN Registration Services Host contains',
	'^Network Information:.*Networks',
	'^Please use the whois server at',
	'^Information and .* for .* Information.',
    ],
    'whois.ripe.net' => [
	'^%',
    ],

    
    'whois.ripn.net' => [
	'^%',
	'Last updated on ',
    ],


    'whois.aero' => [
	'^Access to \.AERO WHOIS',
	'^determining the contents',
	'^Afilias registry database',
	'^Afilias Limited for informational',
	'^guarantee its accuracy',
	'^access\. You agree that',
	'^and that, under no',
	'^enable, or otherwise support',
	'^facsimile of mass unsolicited',
	'^to entities other than the',
	'^\(b\) enable high volume',
	'^queries or data to the systems',
	'^Afilias except as reasonably',
	'^modify existing registrations',
	'^the right to modify these terms',
	'^you agree to abide by this policy',
	'^Name Server: $',
    ],
    'whois.nic.asia' => [
	'^DotAsia WHOIS LEGAL STATEMENT AND',
	'^by DotAsia and the access to',
	'^for information purposes only',
	'^domain name is still available',
	'^the registration records of',
	'^circumstances, be held liable',
	'^be wrong, incomplete, or not',
	'^you agree not to use the',
	'^otherwise support the transmission',
	'^other solicitations whether via',
	'^possible way; or to cause nuisance',
	'^sending \(whether by automated',
	'^volumes or other possible means',
	'^above, it is explicitly forbidden',
	'^in any form and by any means',
	'^quantitatively or qualitatively',
	'^database without prior and explicit',
	'^hereof, or to apply automated',
	'^You agree that any reproduction',
	'^purposes will always be considered',
	'^the content of the WHOIS database',
	'^by this policy and accept that',
	'^WHOIS services in order to protect',
	'^integrity of the database',
	'^Nameservers: $',
    ],
    'whois.biz' => [
	'^>>>> Whois database was last updated',
	'^NeuLevel, Inc\., the Registry',
	'^for the WHOIS database through',
	'^is provided to you for',
	'^persons in determining contents',
	'^NeuLevel registry database',
	'^"as is" and does not guarantee',
	'^agree that you will use this',
	'^circumstances will you use',
	'^support the transmission of',
	'^solicitations via direct mail',
	'^contravention of any applicable',
	'^enable high volume, automated',
	'^\(or its systems\)\. Compilation',
	'^WHOIS database in its entirety',
	'^allowed without NeuLevel',
	'^right to modify or change these',
	'^subsequent notification of any kind',
	'^whatsoever, you agree to abide by',
	'^NOTE\: FAILURE TO LOCATE A RECORD',
	'^OF THE AVAILABILITY OF A DOMAIN NAME',
    ],
    'whois-tel.neustar.biz' => [ # .tel
        '^>>>> Whois database was last updated',
	'Telnic, Ltd., the Registry Operator',
	'for the WHOIS database through an',
	'is provided to you for informational',
	'persons in determining contents of a',
	'Telnic registry database. Telnic makes',
	'"as is" and does not guarantee its',
	'agree that you will use this data',
	'circumstances will you use this data',
	'support the transmission of mass',
	'solicitations via direct mail,',
	'contravention of any applicable',
	'enable high volume, automated,',
	'\(or its systems\). Compilation,',
	'WHOIS database in its entirety,',
	'allowed without Telnic\'s prior',
	'right to modify or change these',
	'subsequent notification of any',
	'whatsoever, you agree to abide',
	'Contact information: Disclosure',
	'of UK and EU Data Protection',
	'contact ID may be available by',
	'system. The information can also',
	'Special Access Service. Visit',
	'.TEL WHOIS DISCLAIMER AND TERMS',
	'By submitting a query and/or',
	'agree to these terms and',
	'This whois information is',
	'Telnic operates the Registry',
	'is provided for information',
	'and shall have no liability',
	'inaccurate.',
	'Telnic is the owner of all',
	'that is made available via this',
	'the information you obtain from',
	'than to obtain information about',
	'for registration or to obtain the',
	'of a domain name that is already',
	'utilise, combine or compile any',
	'to produce a list or database',
	'a license from Telnic to do so.',
	'reason, you will destroy all',
	'using this whois service.',
	'You must not use the information',
	'to: \(a\) allow, enable or otherwise',
	'unsolicited commercial advertising',
	'\(b\) harass any person; or',
    ],
    'whois.cat' => [
	'^%',
    ],
    'ccwhois.verisign-grs.com' => [ # .CC
	'^>>> Last update of',
	'^NOTICE\: The expiration date',
	'sponsorship of the domain name',
	'^currently set to expire',
	'^expiration date of the',
	'^sponsoring registrar\.  Users',
	'^Whois database to view the',
	'^for this registration',
	'^TERMS OF USE\: You are',
	'^database through the use',
	'^automated except as reasonably',
	'^modify existing registrations',
	'^database is provided by',
	'^assist persons in obtaining',
	'^registration record\. VeriSign does',
	'^By submitting a Whois query',
	'^use\: You agree that you may use',
	'^under no circumstances will you',
	'^otherwise support the transmission',
	'^advertising or solicitations via',
	'^\(2\) enable high volume, automated',
	'^VeriSign \(or its computer systems\)',
	'^dissemination or other use of this',
	'^the prior written consent of',
	'^processes that are automated and',
	'^Whois database except as reasonably',
	'^or modify existing registrations',
	'^your access to the Whois database',
	'^operational stability\.  VeriSign',
	'^Whois database for failure to',
	'^reserves the right to modify',
	'^The Registry database contains',
	'^and Registrars\.',
    ],
    'whois.networksolutions.com' => [ # for .net
	'^NOTICE AND TERMS OF USE',
	'^database through the use',
	'^Data in Network Solutions',
	'^purposes only, and to assist',
	'^to a domain name registration',
	'^By submitting a WHOIS query',
	'^You agree that you may use',
	'^circumstances will you use',
	'^the transmission of mass',
	'^via e-mail, telephone, or',
	'^electronic processes that',
	'^compilation, repackaging',
	'^prohibited without the',
	'^high-volume, automated',
	'^database\. Network Solutions',
	'^database in its sole discretion',
	'^querying of the WHOIS database',
	'^Network Solutions reserves',
	'^Get a FREE domain name',
	'^http\:\/\/www\.network',
	'^Visit AboutUs\.org for',
	'^<a href=\"http',
	'-----------',
	'Promote your business',
	'Learn how you can',
	'Learn more at http',
    ],
    'whois.nic.coop' => [
	'\.coop registry WHOIS',
	'^For help on using this',
	'^For more \.coop information',
	'^The domain records that match',
	'-----------',
	'^names only\. Although every',
	'^data, accuracy cannot be guaranteed',
	'^This service is intended only',
	'^use this data only for lawful',
	'^use this data to\: \(a\) allow',
	'^e-mail, telephone, or facsimile',
	'^solicitations to entities',
	'^customers; or \(b\) enable high',
	'^queries or data to the systems',
	'^Registrar, except as reasonably',
	'^existing registrations\. The',
	'^of this Data is expressly prohibited',
	'^dotCoop\. All rights reserved',
	'^at any time\. By submitting this',
	'^BY USING THE WHOIS SERVICE',
	'^GENERATED WITH RESPECT THERETO',
	'^ANY DAMAGES OF ANY KIND ARISING',
	'^INFORMATION PROVIDED BY THE WHOIS',
	'^THE RESULTS OF ANY WHOIS REPORT',
	'^CANNOT BE RELIED UPON IN CONTEMPLATION',
	'^VERIFICATION, NOR DO SUCH RESULTS',
    ],
    'whois.educause.edu' => [
	'^This Registry database',
	'^The data in the EDUCAUSE',
	'^by EDUCAUSE for information',
	'^assist in the process',
	'^or related to \.edu domain',
	'^The EDUCAUSE Whois database',
	'^\.EDU domain\.',
	'^A Web interface for the \.EDU',
	'^available at\: http',
	'^By submitting a Whois query',
	'^will not be used to allow',
	'^the transmission of unsolicited',
	'^solicitations via e-mail',
	'^harvest information from this',
	'^except as reasonably necessary',
	'^domain names\.',
	'^You may use \"%\" as a',
	'^information regarding the use',
	'^type\: help',
    ],
    'whois.dotgov.gov' => [
	'^% DOTGOV WHOIS Server ready',
	'^Please be advised that this whois server only',
    ],
    'whois.nic.mil' => [
	'^To single out one record',
	'^handle, shown in parenthesis',
	'^Please be advised that this whois',
	'^All INTERNET Domain, IP Network Number,',
	'^the Internet Registry, RS.INTERNIC.NET.',
    ],
    'whois.dotmobiregistry.net' => [ # .mobi
	'^mTLD WHOIS LEGAL STATEMENT',
	'^by mTLD and the access to',
	'^for information purposes only.',
	'^domain name is still available',
	'^the registration records of',
	'^circumstances, be held liable',
	'^be wrong, incomplete, or not',
	'^you agree not to use the information',
	'^otherwise support the transmission',
	'^other solicitations whether via',
	'^possible way; or to cause',
	'^sending \(whether by automated,',
	'^volumes or other possible means\)',
	'^above, it is explicitly forbidden',
	'^in any form and by any means',
	'^quantitatively or qualitatively',
	'^database without prior and explicit',
	'^hereof, or to apply automated,',
	'^You agree that any reproduction',
	'^purposes will always be considered',
	'^the content of the WHOIS database.',
	'^by this policy and accept that mTLD',
	'^WHOIS services in order to protect',
	'^integrity of the database.',
    ],
    'whois.museum' => [
        '^%',
    ],
    'whois.nic.name' => [
        '^Disclaimer: The Global Name Registry',
        '^maintain the completeness',
	'^guarantee that',
	'^provided through',
	'^any warranties',
	'^HEREIN OR IN ANY',
	'^ACCEPTED THAT THE GLOBAL',
	'^ANY DAMAGES OF ANY KIND',
	'^REPORT OR THE INFORMATION',
	'^OMISSIONS OR MISSING',
	'^INFORMATION PROVIDED',
	'^CONTEMPLATION OF LEGAL',
	'^DO SUCH RESULTS CONSTITUTE',
	'^results of the Whois',
	'^conditions and limitations',
	'^lawful purposes, in particular',
	'^obligations\.  Illegitimate uses',
	'^limited to, unsolicited email',
	'^other improper purpose',
	'^documented by The Global Name',
	'^for any commercial purpose',
	'^This is the \.name Tiered Access',
	'^string "help"\. A whois web',
	'^A full list of \.name',
	'^\s+--------',
    ],
    'whois.afilias.net' => [ # .info
	'^Access to INFO WHOIS information',
	'^determining the contents of a',
	'^Afilias registry database',
	'^Afilias Limited for informational',
	'^guarantee its accuracy',
	'^access\. You agree that',
	'^and that, under no circumstances',
	'^enable, or otherwise support',
	'^facsimile of mass unsolicited',
	'^to entities other than the data',
	'^\(b\) enable high volume, automated',
	'^queries or data to the systems',
	'^Afilias except as reasonably',
	'^modify existing registrations',
	'^the right to modify these',
	'^you agree to abide by this policy',
	'^Name Server: $',
    ],
    'whois.crsnic.net' => [ # .com  main .net
	'^TERMS OF USE:',
	'^database through',
	'^automated except',
	'^modify existing',
	'^Services\' \(\"VeriSign\"\)',
	'^information purposes only',
	'^about or related to a',
	'^guarantee its accuracy\.',
	'^by the following terms',
	'^for lawful purposes and',
	'^to: (1) allow, enable,',
	'^unsolicited, commercial',
	'^or facsimile; or \(2\)',
	'^that apply to VeriSign',
	'^repackaging, dissemination',
	'^prohibited without the',
	'^use electronic processes',
	'^query the Whois database',
	'^domain names or modify',
	'^to restrict your access',
	'^operational stability\.',
	'^Whois database for',
	'^reserves the right',

	'^NOTICE AND TERMS OF USE:',
	'^Data in Network Solutions',
	'^purposes only, and to assist',
	'^to a domain name registration',
	'^By submitting a WHOIS query,',
	'^You agree that you may use',
	'^circumstances will you use',
	'^the transmission of mass',
	'^via e-mail, telephone, or',
	'^electronic processes that',
	'^compilation, repackaging,',
	'^high-volume, automated,',
	'^database. Network Solutions',
	'^database in its sole discretion,',
	'^querying of the WHOIS database',
	'^Network Solutions reserves the',

	'^NOTICE: The expiration date',
	'^registrar\'s sponsorship of',
	'^currently set to expire\.',
	'^date of the domain name',
	'^registrar.  Users may',
	'^view the registrar\'s',
	'^to: \(1\) allow, enable,',
	'^The Registry database',
	'^Registrars\.',
	'^Domain not found locally,',
	'^Local WHOIS DB must be out',

	'^Whois Server Version',
	'^Domain names in the .com',
	'^with many different',
	'^for detailed information\.',

	'^>>> Last update of whois database',
    ],
    'whois.iana.org' => [
	'^q',
    ],
    'whois.pir.org' => [
        '^NOTICE\: Access to \.ORG WHOIS',
        '^determining the contents',
        '^registry database\. The data',
        '^for informational purposes',
        '^accuracy\.  This service',
        '^that you will use this data',
        '^circumstances will you use',
        '^support the transmission by',
        '^unsolicited, commercial',
	'^the data recipient',
	'^automated, electronic processes',
	'^Registry Operator or any',
	'^necessary to register domain',
	'^rights reserved\. Public Interest',
	'^time\. By submitting this query',
	'^Name Server: $',
    ],
    'whois.registrypro.pro' => [
	'^Whois data provided by RegistryPro',
	'^RegistryPro Whois Terms of Use',
	'^Access to RegistryPro',
	'^is strictly limited to',
	'^guarantee the accuracy',
	'^only for lawful purposes',
	'^data to\: \(a\) allow, enable',
	'^telephone, or facsimile of',
	'^solicitations to entities',
	'^customer; or \(b\) enable',
	'^send queries or data to the',
	'^Operator or any ICANN-accredited',
	'^to register domain  names  or',
	'^reserves the right to modify',
	'^discretion\. Failure to adhere to',
	'^restriction or termination of',
	'^By submitting this query, you',
	'^All rights reserved\.  RegistryPro',
    ],
    'jobswhois.verisign-grs.com' => [ # .JOBS
	'^>>> Last update of',
	'^NOTICE\: The expiration date',
	'sponsorship of the domain name',
	'^currently set to expire',
	'^expiration date of the',
	'^sponsoring registrar\.  Users',
	'^Whois database to view the',
	'^for this registration',
	'^TERMS OF USE\: You are',
	'^database through the use',
	'^automated except as reasonably',
	'^modify existing registrations',
	'^database is provided by',
	'^assist persons in obtaining',
	'^registration record\. VeriSign does',
	'^By submitting a Whois query',
	'^use\: You agree that you may use',
	'^under no circumstances will you',
	'^otherwise support the transmission',
	'^advertising or solicitations via',
	'^\(2\) enable high volume, automated',
	'^VeriSign \(or its computer systems\)',
	'^dissemination or other use of this',
	'^the prior written consent of',
	'^processes that are automated and',
	'^Whois database except as reasonably',
	'^or modify existing registrations',
	'^your access to the Whois database',
	'^operational stability\.  VeriSign',
	'^Whois database for failure to',
	'^reserves the right to modify',
	'^The Registry database contains',
	'^and Registrars\.',
    ],
    'tvwhois.verisign-grs.com' => [ # .TV
	'^>>> Last update of',
	'^NOTICE\: The expiration date',
	'sponsorship of the domain name',
	'^currently set to expire',
	'^expiration date of the',
	'^sponsoring registrar\.  Users',
	'^Whois database to view the',
	'^for this registration',
	'^TERMS OF USE\: You are',
	'^database through the use',
	'^automated except as reasonably',
	'^modify existing registrations',
	'^database is provided by',
	'^assist persons in obtaining',
	'^registration record\. VeriSign does',
	'^By submitting a Whois query',
	'^use\: You agree that you may use',
	'^under no circumstances will you',
	'^otherwise support the transmission',
	'^advertising or solicitations via',
	'^\(2\) enable high volume, automated',
	'^VeriSign \(or its computer systems\)',
	'^dissemination or other use of this',
	'^the prior written consent of',
	'^processes that are automated and',
	'^Whois database except as reasonably',
	'^or modify existing registrations',
	'^your access to the Whois database',
	'^operational stability\.  VeriSign',
	'^Whois database for failure to',
	'^reserves the right to modify',
	'^The Registry database contains',
	'^and Registrars\.',
    ],
    'whois.enom.com' => [ # .TV .CC
        '^=-=-=-=',
        '^Visit AboutUs.org for more',
        '^<a href="',
        '^Registration Service Provided By',
        '^Contact\: \S+@',
        '^Visit\: http\:\/\/qdc\.nl',
        '^Get Noticed on the Internet',
	'^The data in this whois database is provided',
	'^purposes only, that is, to assist you in',
	'^related to a domain name registration record.',
	'^available "as is," and do not guarantee its',
	'^whois query, you agree that you will use this',
	'^purposes and that, under no circumstances will',
	'^enable high volume, automated, electronic',
	'^this whois database system providing you this',
	'^enable, or otherwise support the transmission',
	'^commercial advertising or solicitations via',
	'^mail, or by telephone. The compilation,',
	'^other use of this data is expressly',
	'^consent from us.',
	'^We reserve the right to modify these',
	'^this query, you agree to abide by these',
	'^Version ',
    ],
    'whois.worldsite.ws' => [
	'^Welcome to the .* Whois Server',
	'^Use of this service for any',
	'^than determining the',
	'^in the .* to be registered',
	'^prohibited.',
    ],
    


    'whois.nic.ag' => [
	'^Access to CCTLD WHOIS',
	'^determining the contents',
	'^Afilias registry database',
	'^Afilias Limited for',
	'^guarantee its accuracy',
	'^access\. You agree that',
	'^and that, under no',
	'^enable, or otherwise',
	'^facsimile of mass',
	'^to entities other than',
	'^\(b\) enable high volume',
	'^queries or data to the',
	'^Afilias except as reasonably',
	'^modify existing registrations',
	'^the right to modify these',
	'^you agree to abide by this',
	'^Name Server: $',
    ],
    'whois.nic.at' => [
	'^%',
    ],
    'whois.aunic.net' => [ # .au
	'^%',
    ],
    'whois.dns.be' => [
	'^%',
    ],
    'whois.registro.br' => [
	'^%',
    ],
    'whois.cira.ca' => [
	'^%',
    ],
    'whois.nic.ch' => [
	'^whois: This information is subject',
	'^See http',
    ],
    'whois.nic.ci' => [
	'^All rights reserved',
	'^Copyright \"Generic NIC',
    ],
    'whois.nic.cl' => [
	'^ACE\:',
	'^Última modificación',
	'\(Database last updated on\)',
	'^Más información',
	'www\.nic\.cl\/cgi-bin',
	'^Este mensajes está impreso',
	'^\(This message is printed',
	'^\s+\(\)$',
    ],
    'whois.nic.cx' => [
	'^TERMS OF USE\: You are not',
	'^database through the use of',
	'^automated\.  Whois database',
	'^community on behalf of CoCCA',
	'^The data is for information',
	'^guarantee its accuracy',
	'^by the following terms of use',
	'^for lawful purposes and that',
	'^to\: \(1\) allow, enable, or',
	'^unsolicited, commercial',
	'^or facsimile; or \(2\) enable',
	'^that apply to CoCCA it',
	'^compilation, repackaging, dissemination',
	'^expressly prohibited',
	'^CoCCA Helpdesk',
	'^Domain Information$',
    ],
    'whois.nic.cz' => [
	'^%',
    ],
    'whois.denic.de' => [
	'^%',
    ],
    'whois.nic.dm' => [
	'^TERMS OF USE\: You are not',
	'^database through the use',
	'^automated\.  Whois database',
	'^community on behalf of',
	'^The data is for information',
	'^guarantee its accuracy',
	'^by the following terms of',
	'^for lawful purposes and that',
	'^to\: \(1\) allow, enable',
	'^unsolicited, commercial',
	'^or facsimile; or \(2',
	'^that apply to CoCCA it',
	'^compilation, repackaging,',
	'^expressly prohibited\.',
	'^CoCCA Helpdesk',
	'^Domain Information$',
    ],
    'whois.eenet.ee' => [
	'^The registry database contains',
	'^\.ORG\.EE and \.MED\.EE domains',
	'^Registrar\: EENET',
	'^URL\: http',
    ],
    'whois.dk-hostmaster.dk' => [
	'^#',
    ],
    'whois.eu' => [
	'^%',
    ],
    'whois.ficora.fi' => [
	'^More information is available',
	'^Copyright \(c\) Finnish',
    ],
    'whois.nic.fr' => [
	'^%%',
    ],
    'whois.channelisles.net' => [ # .GG .JE
	'^status\:',
	'^The CHANNELISLES.NET',
	'^for domains registered',
	'^The WHOIS facility is',
	'^basis only\. Island Networks',
	'^or otherwise of information',
	'^the WHOIS, you accept this',
	'^Please also note that some',
	'^unavailable for registration',
	'^for a number of reasons',
	'^Other names for',
	'^nonetheless be unavailable',
	'^WHOIS database copyright',
    ],
    'whois.hkirc.hk' => [
	'^Whois server',
	'^Domain names in the',
	'^and .* can now be registered',
	'^Go to http://www.hkdnr.net.hk',
	'^---------',
	'^The Registry contains ONLY',
	'^.* and .*\\.HK domains.',
    ],
    'whois2.afilias-grs.net' => [ # .GI .HN .LA .SC .VC
	'^Access to CCTLD WHOIS',
	'^determining the contents',
	'^Afilias registry database',
	'^Afilias Limited for',
	'^guarantee its accuracy',
	'^access\. You agree that',
	'^and that, under no',
	'^enable, or otherwise',
	'^facsimile of mass unsolicited',
	'^to entities other than',
	'^\(b\) enable high volume',
	'^queries or data to the',
	'^Afilias except as reasonably',
	'^modify existing registrations',
	'^the right to modify these',
	'^you agree to abide by this policy',
	'^Name Server: $',
    ],
    'whois.nic.gs' => [
	'^TERMS OF USE\: You are not',
	'^database through the use',
	'^automated\.  Whois database',
	'^community on behalf of CoCCA',
	'^The data is for information',
	'^guarantee its accuracy',
	'^by the following terms',
	'^for lawful purposes and',
	'^to\: \(1\) allow, enable',
	'^unsolicited, commercial',
	'^or facsimile; or \(2\) enable',
	'^that apply to CoCCA it',
	'^compilation, repackaging',
	'^expressly prohibited',
	'^CoCCA Helpdesk',
	'^Domain Information$',
    ],
    'whois.hkirc.hk' => [
	'----------------',
	'^ Whois server by HKDNR',
	'^ Domain names in the \.com\.hk',
	'^ \.gov\.hk, idv\.hk\. and',
	'^ Go to http',
	'^ The Registry contains ONLY',
	'^WHOIS Terms of Use',
	'^By using this WHOIS',
	'^The data in HKDNR',
	'^You are not authorised to',
	'^You agree that you will',
	'^a\.    use the data for',
	'^b\.    enable high volume',
	'^c\.    without the prior',
	'^d\.    use such data',
	'^HKDNR in its sole discretion',
	'^HKDNR may modify these',
	'^Company Chinese name', # What is Code Page?
    ],
    'whois.nic.hu' => [
	'% Whois server',
	'^Rights restricted by',
	'Legal usage of this',
	'^abide by the rules',
	'^http\:',
	'A szolgaltatas csak a',
	'^elérhetõ feltételek',
	'^használható legálisan',
    ],
    'whois.domainregistry.ie' => [
	'^%',
    ],
    'whois.isoc.org.il' => [
	'^%',
    ],
    'whois.inregistry.net' => [ # .IN
	'^Access to \.IN WHOIS',
	'^determining the contents',
	'^\.IN registry database',
	'^\.IN Registry for informational',
	'^guarantee its accuracy',
	'^access\. You agree',
	'^and that, under no',
	'^enable, or otherwise',
	'^facsimile of mass unsolicited',
	'^to entities other than',
	'^\(b\) enable high volume',
	'^queries or data to the',
	'^Afilias except as reasonably',
	'^modify existing registrations',
	'^the right to modify these',
	'^you agree to abide by this',
	'^Name Server: $',
    ],
    'whois.isnic.is' => [
	'^%',
    ],
    'whois.nic.it' => [
	'^\*',
    ],
    'whois.jprs.jp' => [
	'^\[\s',
    ],
    'whois.kenic.or.ke' => [
	'^%',
	'^remarks\:',
    ],
    'whois.nic.or.kr' => [
        '^³×ÀÓ¼­¹ö ÀÌ¸§ÀÌ .krÀÌ ¾Æ´Ñ °æ¿ì´',
    ],
    'whois.nic.kz' => [
	'^Whois Server for the KZ',
	'^This server is maintained',
    ],
    'whois.nic.li' => [
	'^whois\: This information',
	'^See http',
    ],
    'whois.domreg.lt' => [
	'^%',
    ],
    'whois.dns.lu' => [
	'^%',
    ],
    'whois.nic.lv' => [
	'^%',
    ],
    'whois.nic.ms' => [
	'^TERMS OF USE\: You are not',
	'^database through the use',
	'^automated\.',
	'^The data is for information',
	'^guarantee its accuracy',
	'^by the following terms of',
	'^for lawful purposes and',
	'^to\: \(1\) allow, enable',
	'^unsolicited, commercial',
	'^or facsimile; or \(2\) enable',
	'^expressly prohibited',
	'^Domain Information$'
    ],
    'whois.nic.mu' => [
	'^TERMS OF USE\: You are not',
	'^database through the use',
	'^automated\.  Whois',
	'^community on behalf of',
	'^The data is for information',
	'^guarantee its accuracy',
	'^by the following terms',
	'^for lawful purposes and',
	'^to\: \(1\) allow, enable',
	'^unsolicited, commercial',
	'^or facsimile; or \(2',
	'^that apply to CoCCA it',
	'^compilation, repackaging',
	'^expressly prohibited',
	'^CoCCA Helpdesk',
	'^Domain Information$',
    ],
    'whois.nic.mx' => [
	'^La informacion que ha',
	'^relacionados con la delegacion',
	'^administrado por NIC Mexico',
	'^Queda absolutamente prohibido',
	'^de Correos Electronicos no',
	'^de productos y servicios',
	'^de NIC Mexico\.',
	'^La base de datos generada',
	'^por las leyes de Propiedad',
	'^sobre la materia\.',
	'^Si necesita mayor informacion',
	'^comunicarse a ayuda@nic',
	'^Si desea notificar sobre correo',
	'^de enviar su mensaje a abuse',
    ],
    'whois.mynic.net.my' => [
	'^Welcome to \.my DOMAIN',
	'----------',
	'For alternative search',
	'whois -h whois\.domainregistry\.my',
	'Type the command as below',
	'Note\: Code is previously',
	'Please note that the query limit is 500 per day from the same IP', # !!!
	'SEARCH BY DOMAIN NAME',
	'^Disclaimer',
	'^MYNIC, the Registry for',
	'^database through a MYNIC-Accredited',
	'^you for informational purposes',
	'^determining contents of a',
	'^database\.',
	'^MYNIC makes this information',
	'^its accuracy\.',
	'^By submitting a WHOIS query',
	'^lawful purposes and that',
	'^\(1\) to allow, enable, or',
	'commercial advertising or',
	'^\(2\) for spamming or',
	'^\(3\) to enable high volume',
	'registry \(or its systems\) or',
	'^\(4\) for any other abusive purpose',
	'^Compilation, repackaging',
	'^its entirety, or of a substantial',
	"^MYNIC's prior written permission",
	'^these conditions at any time',
	'^kind\. By executing this query',
	'^these terms\.',
	'^NOTE\: FAILURE TO LOCATE',
	'^AVAILABILITY OF A DOMAIN NAME',
	'^All domain names are subject to',
	'^Registration of Domain Name',
	'^For details, please visit',
    ],
    'whois.na-nic.com.na' => [
	'^TERMS OF USE\: You are not',
	'^the use of electronic',
	'^WHOIS is NA-NiC',
	'^internet  community\. The',
	'^its  accuracy\.  By submitting',
	'^lawful purposes and',
	'^enable, or otherwise support',
	'^advertising or solicitations',
	'^automated, electronic processes',
	'^member computer systems\). The',
	'^this Data is expressly prohibited',
	'^Copyright 1991, 1995 Dr Lisse',
	'^Domain Information$',
    ],
    'whois.domain-registry.nl' => [
	'Record maintained by',
	'Copyright notice',
	'No part of this publication',
	'retrieval system, or',
	'mechanical, recording, or',
	'Foundation for Internet',
	'Registrars are bound by',
	'except in case of reasonable',
	'and solely for those business',
	'terms and Conditions for',
	'Any use of this material',
	'similar activities is',
	'Stichting Internet',
	'of any such activities or',
	'Copyright \(c\) The',
	'Netherlands \(SIDN\)',
    ],
    'whois.norid.no' => [
	'^%',
    ],
    'whois.nic.nu' => [
	'------------',
	'^\.NU Domain Ltd',
	'^Owner and Administrative Contact information for',
	'^registered in \.nu is',
	'^Copyright by \.NU Domain',
	'^Database last updated',
    ],
    'whois.srs.net.nz' => [
	'^%',
    ],
    'whois.dns.pl' => [
	'^no option',
	'^WHOIS displays data with a',
	'^Registrant data available at',
    ],
    'whois.nic.pm' => [
	'^%%',
    ],
    'whois.nic.pr' => [
	'^Whois Disclaimer',
	'^The data in nic\.pr',
	'^purposes only, that is to',
	'^a domain name registration',
	'^and does not guarantee its',
	'^will use this data only for',
	'^you use this data to',
	'^mass unsolicited, commercial',
	'^mail, including spam or by',
	'^processes or robotic',
	'^purposes that apply to nic',
	'^nation or other use of this',
	'^consent of nic\.pr\. Nic',
	'^mitting this query, you',
    ],
    'whois.nic.re' => [
	'^%%',
    ],
    'whois.rotld.ro' => [
	'^%',
    ],
    'whois.iis.se' => [
	'^#',
    ],
    'whois.nic.net.sg' => [
	'----------',
	'SGNIC WHOIS Server',
	'^The following data is',
	'^Registrant\:',
	'^Note\: With immediate effect',
	'^Contact will not be shown',
	'^Technical Contact details',
	'^Any party who has',
	'^contacts from the domain',
	'^using the organization',
    ],
    'whois.nic.sh' => [
	'^NIC Whois Server',
    ],
    'whois.arnes.si' => [
	'^%',
    ],
    'whois.nic.st' => [
	'^The data in the .* database is provided',
	'^The .* Registry does not guarantee',
	'^The data in the .* database is protected',
	'^By submitting a .* query, you agree that you will',
	'^The Domain Council of .* reserves the right',
    ],
    'whois.nic.tf' => [
	'^%%',
    ],
    'whois.dot.tk' => [
	'Rights restricted by',
	'http\:\/\/www\.dot\.tk',
	'Your selected domain name',
	'cancelled, suspended, refused',
	'It may be available for',
	'In the interim, the rights',
	'transferred to Malo Ni',
	'Please be advised that',
	'Malo Ni Advertising',
	'that was previously',
	'Please review http',
	'Due to restrictions in',
	'about the previous',
	'to the general public',
	'Dot TK is proud to work',
	'agencies to stop spam',
	'other illicit content on',
	'Dot TK Registry directly',
	'usage of this domain by',
	'Record maintained by',
    ],
    'whois.tonic.to' => [
	'^Tonic whoisd',
    ],
    'whois.twnic.net.tw' => [
	'^Registrar:',
	'^URL: http://rs.twnic.net.tw',
    ],
    'whois.net.ua' => [
	'^% This is the Ukrainian',
	'^% Rights restricted by',
	'^%$',
	'^% % \.UA whois',
	'^% ========',
	'% The object shown',
	'% It has been obtained',
	'^% \(whois\.',
	'^%$',
	'^% REDIRECT BEGIN',
	'^% REDIRECT END',
    ],
    'whois.dn.ua' => [
        '^%',
    ],
    'whois.lg.ua' => [
        '^%',
    ],
    'whois.od.ua' => [
        '^%',
    ],
    'whois.nic.uk' => [
	'^This WHOIS information is',
	'^for \.uk domain names',
	'Copyright Nominet UK 1996 - 2009',
	'^You may not access the',
	'^by the terms of use available',
	'^includes restrictions on',
	'^repackaging, recompilation',
	'^or hiding any or all of this',
	'^limits\. The data is provided',
	'^register\. Access may be withdrawn',
	'WHOIS lookup made at',
	'^--',
    ],
    'whois.nic.us' => [
	'^>>>> Whois database was last',
	'^NeuStar, Inc\., the Registry',
	'^information for the WHOIS',
	'^This information is provided',
	'^designed to assist persons',
	'^registration record in the',
	'^information available to you',
	'^By submitting a WHOIS query',
	'^lawful purposes and that',
	'^\(1\) to allow, enable',
	'^unsolicited, commercial',
	'^electronic mail, or by telephone',
	'^data and privacy protection',
	'^electronic processes that',
	'^repackaging, dissemination',
	'^entirety, or of a substantial',
	'prior written permission',
	'^change these conditions at',
	'^of any kind\. By executing',
	'^abide by these terms',
	'^NOTE\: FAILURE TO LOCATE A',
	'^OF THE AVAILABILITY',
	'^All domain names are subject',
	'^rules\.  For details, please',
    ],
    'whois.nic.wf' => [
	'^%%',
    ],
    'whois.nic.yt' => [
	'^%%',
    ],



    'whois.ename.com' => [ # add .com .net .edu
	'^For more information, please go',
    ],
    'whois.ttpia.com' => [ # add .com .net .edu
        ' Welcome to TTpia.com',
        ' Tomorrow is From Today',
    ],
    'whois.directnic.com' => [
	'^By submitting a WHOIS query',
	'^lawful purposes\.  You also agree',
	'^this data to:',
	'^email, telephone,',
	'^or solicitations to',
	'^customers; or to \(b\) enable',
	'^that send queries or data to',
	'^ICANN-Accredited registrar\.',
	'^The compilation, repackaging,',
	'^data is expressly prohibited',
	'^directNIC.com\.',
	'^directNIC.com reserves the right',
	'^database in its sole discretion,',
	'^excessive querying of the database',
	'^this policy\.',
	'^directNIC reserves the right to',
	'^NOTE: THE WHOIS DATABASE IS A',
	'^LACK OF A DOMAIN RECORD DOES',
	'^Intercosmos Media Group, Inc',
	'^Registrar WHOIS database for',
	'^may only be used to assist in',
	'^registration record\.',
	'^directNIC makes this information',
	'^its accuracy\.',
    ],
    'whois.alldomains.com' => [
	'^MarkMonitor.com - ',
	'^------------------',
	'^For Global Domain ',
	'^and Enterprise DNS,',
	'^------------------',
	'^The Data in MarkMon',
	'^for information pur',
	'^about or related to',
	'^does not guarantee ',
	'^that you will use t',
	'^circumstances will ',
	'^support the transmi',
	'^solicitations via e',
	'^electronic processe',
	'^MarkMonitor.com res',
	'^By submitting this ',
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
	'^by this policy.  All rights reserved.',
    ],
    'whois.worldnames.net' => [
	'^----------------------------------',
	'^.\\w+ Domain .* Whois service',
	'^Copyright by .* Domain LTD',
	'^----------------------------------',
	'^Database last updated',
    ],
    'whois.godaddy.com' => [
	'^The data contained in GoDaddy.com,',
	'^while believed by the company to be',
	'^with no guarantee or warranties',
	'^information is provided for the sole',
	'^in obtaining information about domain',
	'^Any use of this data for any other',
	'^permission of GoDaddy.com, Inc.',
	'^you agree to these terms of usage',
	'^you agree not to use this data to',
	'^dissemination or collection of this',
	'^purpose, such as the transmission of',
	'^and solicitations of any kind, including',
	'^not to use this data to enable high volume,',
	'^processes designed to collect or compile',
	'^including mining this data for your own',
	'^Please note: the registrant of the domain',
	'^in the "registrant" field.  In most cases,',
	'^is not the registrant of domain names listed',
    ],
    'whois.paycenter.com.cn' => [
	'^The Data in Paycenter\'s WHOIS database is',
	'^for information purposes, and to assist',
	'^information about or related to a domain',
	'^record\.',
	'^Paycenter does not guarantee its accuracy.',
	'^a WHOIS query, you agree that you will use',
	'^for lawful purposes and that, under no',
	'^you use this Data to:',
	'^\(1\) allow, enable, or otherwise support',
	'^of mass unsolicited, commercial',
	'^via e-mail \(spam\); or',
	'^\(2\) enable high volume, automated,',
	'^apply to Paycenter or its systems.',
	'^Paycenter reserves the right to modify',
	'^By submitting this query, you agree to',
    ],
    'whois.dotster.com' => [
	'^The information in this whois database is',
	'^purpose of assisting you in obtaining',
	'^name registration records. This information',
	'^and we do not guarantee its accuracy. By',
	'^query, you agree that you will use this',
	'^purposes and that, under no circumstances',
	'^to: \(1\) enable high volume, automated,',
	'^stress or load this whois database system',
	'^information; or \(2\) allow,enable, or',
	'^transmission of mass, unsolicited, commercial',
	'^solicitations via facsimile, electronic mail,',
	'^entitites other than your own existing customers.',
	'^compilation, repackaging, dissemination or other',
	'^is expressly prohibited without prior written',
	'^company. We reserve the right to modify these',
	'^time. By submitting an inquiry, you agree to',
	'^and limitations of warranty.  Please limit',
	'^minute and one connection.',
    ],
    'whois.nordnet.net' => [
	'^Serveur Whois version',
	'^\*\*\*\*\*\*\*\*\*',
	'^\* Base de Donnees des domaines COM, NET et ORG',
	'^\* enregistres par NORDNET.                    ',
	'^\* Ces informations sont affichees par le serve',
	'^\* Whois de NORDNET, le Registrar du           ',
	'^\* Groupe FRANCE-TELECOM                       ',
	'^\* Elles ne peuvent etre utilisees sans l accor',
	'^\* prealable de NORDNET.                       ',
	'^\*                                             ',
	'^\* Database of registration for COM, NET and   ',
	'^\* ORG by NORDNET.                             ',
	'^\* This informations is from NORDNET s Whois   ',
	'^\* Server, the Registrar for the               ',
	'^\* Group FRANCE-TELECOM.                       ',
	'^\* Use of this data is strictly prohibited with',
	'^\* out proper authorisation of NORDNET.',
	'^Deposez votre domaine sur le site http://www.nordnet.net',
	'^Copyright Nordnet Registrar',
    ],
    'whois.nsiregistry.net' => [
	'^Domain names in the \.com and',
	'^with many different competing',
	'^for detailed information',
	'^>>> Last update of whois database',
	'^NOTICE: The expiration date',
	"^registrar's sponsorship",
	'^currently set to expire',
	'^date of the domain name',
	'^registrar\.  Users may',
	'^view the registrar',
	'^TERMS OF USE: You are not',
	'^database through the use',
	'^automated except as reasonably',
	'^modify existing registrations',
	'is provided by VeriSign for $',
	'^information purposes only',
	'^about or related to a domain',
	'^guarantee its accuracy',
	'^by the following terms of',
	'^for lawful purposes and',
	'^to: \(1\) allow, enable',
	'^unsolicited, commercial',
	'^or facsimile; or \(2\) enable',
	'^that apply to VeriSign',
	'^repackaging, dissemination',
	'^prohibited without the prior',
	'^use electronic processes that',
	'^query the Whois database except',
	'^domain names or modify existing',
	'^to restrict your access to the',
	'^operational stability\.  VeriSign',
	'^Whois database for failure to',
	'^reserves the right to modify',
	'^The Registry database contains',
	'^Registrars\.$',
    ],
);

our %exceed = (
    'whois.eu' => 'Excessive querying, grace period of',
    'whois.dns.lu' => 'Excessive querying, grace period of',
    'whois.mynic.net.my' => 'Query limitation is',
    'whois.ripn.net' => 'exceeded allowed connection rate',
    'whois.domain-registry.nl' => 'too many requests',
    'whois.nic.uk' => 'and will be replenished',
    'whois.networksolutions.com' => 'contained within a list of IP addresses that may have failed',
    'whois.worldsite.ws' => 'You exceeded the maximum',
    'whois.tucows.com'  => '(Maximum Daily connection limit reached|exceeded maximum connection limit)',
    'whois.centralnic.com'  => 'Query rate of \\d+',
    'whois.pir.org'  => 'WHOIS LIMIT EXCEEDED',
    'whois.nic.ms'   => 'Look up quota exceeded',
    'whois.nic.gs'   => 'look up quota exceeded',
);

our $default_ban_time = 60;
our %ban_time = (
    'whois.ripn.net'  => 60,
);

1;

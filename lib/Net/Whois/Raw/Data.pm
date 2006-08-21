package Net::Whois::Raw::Data;

use strict;
use vars qw(%notfound %strip %servers %exceed @www_whois %ip_whois_servers);

@www_whois = qw(
    IN
    KZ
    SPB.RU
    MSK.RU
);

%servers = qw(
    NS     whois.internic.net
    RIPE   whois.ripe.net
    IP     whois.arin.net

    AERO   whois.aero
    ARPA   whois.arin.net
    BIZ    whois.biz
    CAT    whois.cat
    COM    whois.crsnic.net
    COOP   whois.nic.coop
    EDU    whois.educause.edu
    GOV    whois.dotgov.gov
    INFO   whois.afilias.net
    INT    whois.iana.org
    MIL    whois.nic.mil
    MOBI   whois.dotmobiregistry.net
    MUSEUM whois.museum
    NAME   whois.nic.name
    NET    whois.crsnic.net
    ORG    whois.pir.org
    PRO    whois.registrypro.pro

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
    CI  whois.nic.cI
    CL  Whois.nic.cl
    CN  whois.cnnic.net.cn
    CX  whois.nic.cx
    CZ  whois.nic.cz
    DE  whois.denic.de
    DK  whois.dk-hostmaster.dk
    EE  whois.eenet.ee
    EU  whois.eu
    FI  whois.ficora.fi
    FR  whois.nic.fr
    GG  whois.channelisles.net
    GI  whois2.afilias-grs.net
    GS  whois.nic.gs
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
    KZ  www.nic.kz
    LA  whois2.afilias-grs.net
    LI  whois.nic.li
    LT  whois.domreg.lt
    LU  whois.dns.lu
    LV  whois.nic.lv
    MG  whois.nic.mg
    MN  whois.nic.mn
    MS  whois.adamsnames.tc
    MX  whois.nic.mx
    MY  whois.mynic.net.my
    NA  whois.na-nic.com.na
    NL  whois.domain-registry.nl
    NO  whois.norid.no
    NU  whois.nic.nu
    NZ  whois.srs.net.nz
    PL  whois.dns.pl
    PM  whois.nic.pm
    PR  whois.uprr.pr
    RE  whois.nic.re
    RO  whois.rotld.ro
    RU  whois.ripn.net
    SB  whois.nic.net.sb
    SC  whois2.afilias-grs.net
    SE  whois.iis.se
    SG  whois.nic.net.sg
    SH  whois.nic.sh
    SI  whois.arnes.si
    ST  whois.nic.st
    SU  whois.ripn.net
    TC  whois.adamsnames.tc
    TF  whois.nic.tf
    TK  whois.dot.tk
    TL  whois.nic.tl
    TM  whois.nic.tm
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

    CC  whois.nic.cc
    DO  ns.nic.do
    HU  whois.nic.hu
    PT  whois.dns.pt
    TO  whois.tonic.to
    WS  whois.worldsite.ws

    XN---P1AG	ru.whois.i-dns.net
    XN---P1AG	ru.whois.i-dns.net
    XN---J1AEF	whois.i-dns.net
    XN---E1APQ	whois.i-dns.net
    XN---C1AVG	whois.i-dns.net

    COM.RU	whois.ripn.net
    NET.RU	whois.ripn.net
    ORG.RU	whois.ripn.net
    PP.RU	whois.ripn.net
    SPB.RU	whois.relcom.ru
    MSK.RU	whois.relcom.ru
    RU.NET	whois.relcom.ru
    YES.RU	whois.regtime.net

    UK.COM      whois.centralnic.com
    UK.NET      whois.centralnic.com
    GB.COM      whois.centralnic.com
    GB.NET      whois.centralnic.com
    EU.COM      whois.centralnic.com
);

# These serve only several subdomains
#         ZA  apies.frd.ac.za

%ip_whois_servers = qw(
    AFRINIC	whois.afrinic.net
    APNIC	whois.apnic.net
    ARIN	whois.arin.net
    LACNIC	whois.lacnic.net
    RIPE	whois.ripe.net

    JPNIC	whois.nic.ad.jp
    KRNIC	whois.krnic.net
);


%notfound = (
    'whois.arin.net' => '^No match for',
    'whois.ripe.net' => 'No entries found',

    'whois.biz' => '^Not found:',
    'whois.nic.coop' => 'No Objects Found',
    'whois.afilias.net' => '^NOT FOUND',
    'whois.nic.mil' => '^No match for',
    'whois.museum' => '^No information for',

    'whois.nic.at' => 'nothing found',
    'whois.aunic.net' => 'No Data Found',
    'whois.dns.be' => '^Status:      FREE',
    'whois.registro.br' => 'No match for',
    'whois.cira.ca' => 'Status:\\s*UNAV',
    'whois.nic.ch' => '^We do not have an entry in our database matching your',
    'whois.nic.cl' => 'Invalid domain name',
    'whois.nic.cx' => '^No match for',
    'whois.nic.cz' => 'No data found',
    'whois.denic.de' => 'No entries found',
    'whois.eu' => '^Status:      FREE',
    'whois.nic.fr' => 'No entries found',
    'whois.hkirc.hk' => '^No Match for',
    'whois.nic.hu' => 'No match',
    'whois.domainregistry.ie' => 'There was no match',
    'whois.isoc.org.il' => 'No data was found',
    'whois.inregistry.net' => '^No matches',
    'whois.isnic.is' => 'No entries found',
    'whois.nic.it' => '^No entries found',
    'whois.jprs.jp' => 'No match',
    'whois.nic.or.kr' => 'Above domain name is not registered',
    'whois2.afilias-grs.net' => '^NO MATCH for',
    'whois.domreg.lt' => 'No matches found',
    'whois.dns.lu' => 'No entries found',
    'whois.nic.mx' => '^Nombre del Dominio:',
    'whois.mynic.net.my' => 'does not Exist in database',
    'whois.na-nic.com.na' => 'No records matching',
    'whois.domain-registry.nl' => 'invalid query',
    'whois.norid.no' => 'no matches',
    'whois.srs.net.nz' => 'query_status: 220 Available',
    'whois.dns.pl' => '^Domain name .* does not exists',
    'whois.dns.pt' => 'no match',
    'whois.rotld.ro' => 'No entries found',
    'whois.ripn.net' => 'No entries found',
    'whois.iis.se' => 'No data found',
    'whois.nic.net.sg' => 'NO entry found',
    'whois.nic.sh' => 'Not available',
    'whois.arnes.si' => 'No entries found',
    'whois.nic.st' => '^No entries found',
    'whois.adamsnames.tc' => 'is not a domain controlled by',
    'whois.twnic.net.tw' => '^No Found',
    'whois.net.ua' => 'No entries found for domain',
    'whois.nic.uk' => '^\\s*No match for',
    'whois.nic.ve' => 'No match for',

    'whois.nic.cc' => '^No match for',
    'whois.tonic.to' => 'No match for',
    'whois.worldsite.ws' => 'No match for',

    'whois.networksolutions.com' => '(?i)no match',
    'whois.melbourneit.com' => '^Invalid/Unsupported whois name check',

    'apies.frd.ac.za' => 'No information is available',
    'whois.worldnames.net' => 'NO MATCH for domain',
    'whois.nic.tj' => '^No match for',
    'whois.gdns.net' => '^Domain Not Found',
    'whois.thnic.net' => 'No entries found',
);

%strip = (
    'whois.crsnic.net' => [
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
	'^$',
    ],

    'whois.arin.net' => [
	'^The ARIN Registration Services Host contains',
	'^Network Information:.*Networks',
	'^Please use the whois server at',
	'^Information and .* for .* Information.',
    ],
    'whois.ripe.net' => [
	'^%',
    ],

    'whois.nic.coop' => [
	'^%',
	'^ The .COOP Registration',
	'^ Please use the',
    ],
    'whois.nic.mil' => [
	'^To single out one record',
	'^handle, shown in parenthesis',
	'^Please be advised that this whois',
	'^All INTERNET Domain, IP Network Number,',
	'^the Internet Registry, RS.INTERNIC.NET.',
    ],

    'whois.nic.at' => [
	'^%',
    ],
    'whois.aunic.net' => [
	'^%',
    ],
    'whois.dns.be' => [
	'^%-',
    ],
    'whois.registro.br' => [
	'^%',
    ],
    'whois.nic.ch' => [
	'^whois: This information is subject',
	'^See http',
    ],
    'whois.nic.cl' => [
	'^cl.cl:',
	'^Más información: http://www.nic.cl/',
    ],
    'whois.nic.cx' => [
	'^ Registrar: Christmas Island',
	'^ Whois Server: whois.nic.cx',
    ],
    'whois.nic.cz' => [
	'^%',
    ],
    'whois.denic.de' => [
	'^%',
    ],
    'whois.eu' => [
	'^%-',
    ],
    'whois.nic.fr' => [
	'^Tous droits reserves par copyright.',
	'^Voir http://www.nic.fr',
	'^Rights restricted by copyright.',
	'^See http://www.nic.fr/outils',
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
    'whois.nic.hu' => [
	'^%',
    ],
    'whois.domainregistry.ie' => [
	'^%',
    ],
    'whois.isoc.org.il' => [
	'^%',
    ],
    'whois.isnic.is' => [
	'^%',
    ],
    'whois.jprs.jp' => [
	'^\[',
    ],
    'whois.nic.or.kr' => [
	'^Korea Internet Information Service',
	'^20\\d\\d³â 7¿ù 2ÀÏºÎÅÍ´Â °³¼±µÈ Whois',
	'^.com, .net, .org',
    ],
    'whois2.afilias-grs.net' => [
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
	'^   policy.',
    ],
    'whois.domreg.lt' => [
	'^%',
    ],
    'whois.dns.lu' => [
	'^%',
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
	'^internacionales sobre la materia.',
    ],
    'whois.domain-registry.nl' => [
	'Rights restricted by copyright',
	'http://www.domain-registry.nl',
    ],
    'whois.norid.no' => [
	'^%',
    ],
    'whois.srs.net.nz' => [
	'^%',
    ],
    'whois.dns.pl' => [
	'^%',
    ],
    'whois.rotld.ro' => [
	'^%',
    ],
    'whois.ripn.net' => [
	'^%',
	'Last updated on ',
    ],
    'whois.iis.se' => [
	'^#',
    ],
    'whois.nic.net.sg' => [
	'^\\*',
    ],
    'whois.nic.sh' => [
	'^NIC Whois Server',
    ],
    'whois.arnes.si' => [
	'^\\*',
    ],
    'whois.nic.st' => [
	'^The data in the .* database is provided',
	'^The .* Registry does not guarantee',
	'^The data in the .* database is protected',
	'^By submitting a .* query, you agree that you will',
	'^The Domain Council of .* reserves the right',
    ],
    'whois.tonic.to' => [
	'^Tonic whoisd',
    ],
    'whois.twnic.net.tw' => [
	'^Registrar:',
	'^URL: http://rs.twnic.net.tw',
    ],
    'whois.net.ua' => [
	'^%',
    ],
    'whois.nic.uk' => [
	'^The .* Registration Host contains information',
	'^registrations in the .*co.uk',
	'and .*\\.uk second-level domains.',
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
	'^submitting this query,',
    ],
    'whois.worldsite.ws' => [
	'^Welcome to the .* Whois Server',
	'^Use of this service for any',
	'^than determining the',
	'^in the .* to be registered',
	'^prohibited.',
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
	'^this query, you',
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
);

%exceed = (
    'whois.eu' => 'Excessive querying, grace period of',
    'whois.dns.lu' => 'Excessive querying, grace period of',
    'whois.ripn.net' => 'excessive querying of the WHOIS database',
    'whois.domain-registry.nl' => 'too many requests',
    'whois.nic.uk' => 'and will be replenished',
);

1;

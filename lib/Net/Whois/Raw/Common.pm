package Net::Whois::Raw::Common;

use strict;
require Net::Whois::Raw::Data;

# get whois from cache 
sub get_from_cache {
    my ($query, $cache_dir, $cache_time) = @_;

    return undef unless $cache_dir;
    mkdir $cache_dir unless -d $cache_dir;
    
    my $now = time;
    # clear the cache
    foreach ( glob("$cache_dir/*") ) {
        my $mtime = ( stat($_) )[9] or next;
        my $elapsed = $now - $mtime;
        unlink $_ if ( $elapsed / 60 >= $cache_time );
    }

    my $result;
    if ( -e "$cache_dir/$query.00" ) {
        my $level = 0;
        while ( open( CACHE, "<$cache_dir/$query.".sprintf( "%02d", $level ) ) ) {
            $result->[$level]->{srv} = <CACHE>;
            chomp $result->[$level]->{srv};
            $result->[$level]->{text} = join "", <CACHE>;
            $level++;
        }
    }
    
    return $result;
}

# write whois to cache
sub write_to_cache {
    my ($query, $result, $cache_dir) = @_;

    return unless $cache_dir && $result;
    mkdir $cache_dir unless -d $cache_dir;
    
    my $level = 0;
    foreach my $res ( @{$result} ) {
        my $postfix = sprintf("%02d", $level);
        if ( open( CACHE, ">$cache_dir/$query.$postfix" ) ) {
            print CACHE $res->{srv} ? $res->{srv} :
                ( $res->{server} ? $res->{server} : '')
                , "\n";
                
            print CACHE $res->{text} ? $res->{text} :
                ( $res->{whois} ? $res->{whois} : '' );
            
            close(CACHE);            
            chmod 0666, "$cache_dir/$query.$postfix";
        }
        $level++;
    }
    
}

# remove copyright messages, check for existance
sub process_whois {
    my ($query, $server, $whois, $CHECK_FAIL, $OMIT_MSG, $CHECK_EXCEED) = @_;

    $server = lc $server;
    my ($name, $tld) = split_domain($query);
    
    if ($tld eq 'mu') {
        if ($whois =~ /.MU Domain Information\n(.+?\n)\n/s) {
            $whois = $1;
        }
    }
    
    $whois = $Net::Whois::Raw::POSTPROCESS{$server}->($whois)
        if defined $Net::Whois::Raw::POSTPROCESS{$server};

    return $whois unless $CHECK_FAIL || $OMIT_MSG || $CHECK_EXCEED;

    my $exceed = $Net::Whois::Raw::Data::exceed{$server};
    if ($CHECK_EXCEED && $exceed && $whois =~ /$exceed/s) {
        return $whois, "Connection rate exceeded";
    }
    
    my %notfound = %Net::Whois::Raw::Data::notfound;
    my %strip = %Net::Whois::Raw::Data::strip;
    
    my $notfound = $notfound{$server};
    my @strip = $strip{$server} ? @{$strip{$server}} : ();
    my @lines;
    MAIN: foreach (split(/\n/, $whois)) {
        if ( $CHECK_FAIL && $notfound && /$notfound/ ) {
            return undef, "Not found";
        };
        if ($OMIT_MSG) {
            foreach my $re (@strip) {
                next MAIN if (/$re/);
            }
        }
        s/^\s+//;
        
        push(@lines, $_);
    }
    
    $whois = join("\n", @lines, "");
    $whois = strip_whois($whois) if $OMIT_MSG > 1;

    return undef, "Not found" if $CHECK_FAIL > 1 && !check_existance($whois);
    
    return $whois, undef;
}

#  check if whois info found
sub check_existance {
    $_ = $_[0];

    return undef if
        /is unavailable/is ||
        /No entries found for the selected source/is ||
        /Not found:/s ||
        /No match\./s ||
        /Not found/is &&
            !/ your query returns "NOT FOUND"/ &&
            !/Domain not found locally/ ||
        /No match for/is ||
        /No Objects Found/s ||
        /No domain records were found/s ||
        /No such domain/s ||
        /No entries found in the /s ||
        /Could not find a match for/s ||
        /Unable to find any information for your query/s ||
        /is not registered/s ||
        /no matching record/s ||
	/No match found\n/ ||
        /NOMATCH/s;

    return 1;
}

# strip copyrights, deprecated, use Data::strip
sub strip_whois {
    $_ = $_[0];

    s/The Data.+(policy|connection)\.\n//is;
    s/% NOTE:.+prohibited\.//is;
    s/Disclaimer:.+\*\*\*\n?//is;
    s/NeuLevel,.+A DOMAIN NAME\.//is;
    s/For information about.+page=spec//is;
    s/NOTICE: Access to.+this policy.//is;
    s/The previous information.+completeness\.//s;
    s/NOTICE AND TERMS OF USE:.*modify these terms at any time\.//s;

    s/By submitting a WHOIS query.+?DOMAIN AVAILABILITY.\n?//s;
    s/Registration and WHOIS.+?its accuracy.\n?//s;
    s/Disclaimer:.+?\*\*\*\n?//s;
    s/The .COOP Registration .+ Information\.//s;
    s/Whois Server Version \d+\.\d+.//is;
    s/NeuStar,.+www.whois.us\.//is;
    s/% .+?\n//gs;
    s/Domain names can now be registered.+?for detailed information.//s;

    s/^\n+//s;
    s/(?:\s*\n)+$/\n/s;

    return $_;
}

# get whois-server for domain
sub get_server {
    my ($dom, $USE_CNAME) = @_;
    
    my $tld = uc get_dom_tld( $dom );
    $tld =~ s/^XN--(\w)/XN---$1/;

    if ( grep { $_ eq $tld } @Net::Whois::Raw::Data::www_whois ) {
        return 'www_whois';
    }

    my $cname = "$tld.whois-servers.net";
    my $srv = $Net::Whois::Raw::Data::servers{$tld} || $cname;
    $srv = $cname if $USE_CNAME && gethostbyname($cname);

    return $srv;
}

sub get_real_whois_query{
    my ($whoisquery, $srv, $is_ns) = @_;
    
    $is_ns = 1 if $whoisquery =~ s/.NS$//i;

    if ($srv eq 'whois.crsnic.net' && domain_level($whoisquery) == 2) {
        $whoisquery = "domain $whoisquery";
    }
    elsif ($srv eq 'whois.denic.de') {
        $whoisquery = "-T dn,ace -C ISO-8859-1 $whoisquery";
    }
    elsif ($srv eq 'whois.nic.name') {
        if ( $is_ns ) {
            $whoisquery = "nameserver=$whoisquery";
	}
	else {
	    $whoisquery = "domain=$whoisquery";
	}
    }
    elsif ( $is_ns && $srv eq 'whois.nsiregistry.net' ) {
        $whoisquery = "nameserver = $whoisquery";
    }
    
    return $whoisquery;
}

# get domain TLD
sub get_dom_tld {
    my ($dom) = @_;

    my $tld;
    if ( is_ipaddr($dom) ) {
        $tld = "IP";
    }
    elsif ( domain_level($dom) == 1 ) {
        $tld = "NOTLD";
    }
    else { 
        my @alltlds = keys %Net::Whois::Raw::Data::servers;
        @alltlds = sort { dlen($b) <=> dlen($a) } @alltlds;
        foreach my $awailtld (@alltlds) {
            $awailtld = lc $awailtld;
            if ($dom =~ /(.+?)\.($awailtld)$/) {
                $tld = $2;
                last;
            }
        }
        unless ($tld) {
            my @tokens = split(/\./, $dom);
            $tld = $tokens[-1]; 
        }
    }

    return $tld;
}

# get URL for query via HTTP
# %param: domain*
sub get_http_query_url {
    my ($domain) = @_;    
    
    my ($name, $tld) = split_domain($domain);
    my ($url, %form);

    if ($tld eq 'tv') {
        $url = "http://www.tv/cgi-bin/whois.cgi?domain=$name&tld=tv";
    }
    elsif ($tld eq 'mu') {
        $url = 'http://www.mu/cgi-bin/mu_whois.cgi';
        $form{whois} = $name;
    }
    elsif ($tld eq 'spb.ru' || $tld eq 'msk.ru') {
        $url = "http://www.relcom.ru/Services/Whois/?fullName=$name.$tld";
    }
    elsif ($tld eq 'ru' || $tld eq 'su') {
        $url = "http://www.nic.ru/whois/?domain=$name.$tld";
    }
    elsif ($tld eq 'ip') {
        $url = "http://www.nic.ru/whois/?ip=$name";
    }
    elsif ($tld eq 'in') {
        $url = "http://www.registry.in/cgi-bin/whois.cgi?whois_query_field=$name";
    }
    elsif ($tld eq 'cn') {
        $url = "http://ewhois.cnnic.net.cn/whois?value=$name.$tld&entity=domain";
    }
    elsif ($tld eq 'ws') {
        $url = "http://worldsite.ws/utilities/lookup.dhtml?domain=$name&tld=$tld";
    }
    elsif ($tld eq 'kz') {
        $url = "http://www.nic.kz/cgi-bin/whois?query=$name.$tld&x=0&y=0";
    }
    elsif ($tld eq 'vn') {
	$url = "http://www.vnnic.vn/jsp/jsp/tracuudomain1.jsp";

        $form{cap2} = ".$tld"; 
        $form{referer} = 'http://www.vnnic.vn/english/';
        $form{domainname1} = $name;
    }
    elsif ($tld eq 'ac') {
        $url = "http://nic.ac/cgi-bin/whois?textfield=$name.$tld";
    }
    elsif ($tld eq 'bz') {
	my $domcode = unpack( 'H*', "$name.$tld" );
        $url = 'http://www.belizenic.bz/cgi-bin/Registrar_YTest?action=whois&action2=whois&domain='.$domcode;
    }
        
    return $url, %form;
}

# Parse content received from HTTP server
# %param: resp*, tld*
sub parse_www_content {
    my ($resp, $tld, $CHECK_EXCEED) = @_;
     
    chomp $resp;
    $resp =~ s/\r//g;

    my $ishtml;

    if ($tld eq 'tv') {

        return 0 unless
        $resp =~ /(<TABLE BORDER="0" CELLPADDING="4" CELLSPACING="0" WIDTH="95%">.+?<\/TABLE>)/is;
        $resp = $1;
        $resp =~ s/<BR><BR>.+?The data in The.+?any time.+?<BR><BR>//is;
        return 0 if $resp =~ /Whois information is not available for domain/s;
        $ishtml = 1;

    }
    elsif ( $tld eq 'spb.ru' || $tld eq 'msk.ru' ) {

        $resp = koi2win( $resp );
        return undef unless $resp =~ m|<TABLE BORDER="0" CELLSPACING="0" CELLPADDING="2"><TR><TD BGCOLOR="#990000"><TABLE BORDER="0" CELLSPACING="0" CELLPADDING="20"><TR><TD BGCOLOR="white">(.+?)</TD></TR></TABLE></TD></TR></TABLE>|s;
        $resp = $1;

        return 0 if $resp =~ m/СВОБОДНО/;

        if ($resp =~ m|<PRE>(.+?)</PRE>|s) {
            $resp = $1;
        }
	elsif ($resp =~ m|DNS \(name-серверах\):</H3><BLOCKQUOTE>(.+?)</BLOCKQUOTE><H3>Дополнительную информацию можно получить по адресу:</H3><BLOCKQUOTE>(.+?)</BLOCKQUOTE>|) {
            my $nameservers = $1;
            my $emails = $2;
            my (@nameservers, @emails);
            while ($nameservers =~ m|<CODE CLASS="h2black">(.+?)</CODE>|g) {
                push @nameservers, $1;
            }
            while ($emails =~ m|<CODE CLASS="h2black"><A HREF=".+?">(.+?)</A></CODE>|g) {
                push @emails, $1;
            }
            if (scalar @nameservers && scalar @emails) {
                $resp = '';
                foreach my $ns (@nameservers) {
                    $resp .= "nserver:      $ns\n";
                }
                foreach my $email (@emails) {
                    $resp .= "e-mail:       $email\n";
                }
            }
        }

    }
    elsif ($tld eq 'mu') {

        return 0 unless
        $resp =~ /(<p><b>Domain Name:<\/b><br>.+?)<hr width="75%">/s;
        $resp = $1;
        $ishtml = 1;

    }
    elsif ( $tld eq 'ru' || $tld eq 'su' ) {

        $resp = koi2win($resp);
        (undef, $resp) = split('<script>.*?</script>',$resp);
        ($resp) = split('</td></tr></table>', $resp);
        $resp =~ s/&nbsp;/ /gi;
        $resp =~ s/<([^>]|\n)*>//gi;

        return 0 if $resp=~ m/Доменное имя .*? не зарегистрировано/i;
        $resp = 'ERROR' if $resp =~ m/Error:/i || $resp !~ m/Информация о домене .+? \(по данным WHOIS.RIPN.NET\):/;;
        #TODO: errors
    }
    elsif ($tld eq 'ip') {

        return 0 unless $resp =~ m|<p ID="whois">(.+?)</p>|s;

        $resp = $1;
        
        $resp =~ s|<a.+?>||g;
        $resp =~ s|</a>||g;
        $resp =~ s|<br>||g;
        $resp =~ s|&nbsp;| |g;

    }
    elsif ($tld eq 'in') {

        if ( $resp =~ /Domain ID:\w{3,10}-\w{4}\n(.+?)\n\n/s ) {
            $resp = $1;
            $resp =~ s/<br>//g;
        } 
	else {
            return 0;
        }

    }
    elsif ($tld eq 'cn') {

        if ($resp =~ m|<table border=1 cellspacing=0 cellpadding=2>\n\n(.+?)\n</table>|s) {
            $resp = $1;
            $resp =~ s|<a.+?>||isg;
            $resp =~ s|</a>||isg;
            $resp =~ s|<font.+?>||isg;
            $resp =~ s|</font>||isg;
            $resp =~ s|<tr><td class="t_blue">.+?</td><td class="t_blue">||isg;
            $resp =~ s|</td></tr>||isg;
            $resp =~ s|\n\s+|\n|sg;
            $resp =~ s|\n\n|\n|sg;
        }
	else {
            return 0;
        }

    }
    elsif ($tld eq 'ws') {

	if ($resp =~ /Whois information for .+?:(.+?)<table>/s) {
	    $resp = $1;
            $resp =~ s|<font.+?>||isg;
            $resp =~ s|</font>||isg;

            $ishtml = 1;
	}
	else {
	    return 0;
	}

    }
    elsif ($tld eq 'kz') {
    
	if ($resp =~ /Domain Name\.{10}/s && $resp =~ /<pre>(.+?)<\/pre>/s) {
	    $resp = $1;
	}
	else {
	    return 0;
	}
    }
    elsif ($tld eq 'vn') {

        if ($resp =~ /\(\s*?(Domain.*?:\s*(?:Available|registered))\s*?\)/i )  {
            $resp = $1;
        }
	else {
            return 0;
        }

        #
	# if ($resp =~/#ENGLISH.*?<\/tr>(.+?)<\/table>/si) {
	#    $resp = $1;
	#    $resp =~ s|</?font.*?>||ig;
	#    $resp =~ s|&nbsp;||ig;
	#    $resp =~ s|<br>|\n|ig;
	#    $resp =~ s|<tr>\s*<td.*?>\s*(.*?)\s*</td>\s*<td.*?>\s*(.*?)\s*</td>\s*</tr>|$1 $2\n|isg;
	#    $resp =~ s|^\s*||mg;
	# 
    }
    elsif ($tld eq 'ac') {

        if ($CHECK_EXCEED && $resp =~ /too many requests/is) {
            die "Connection rate exceeded";
        }
	elsif ($resp =~ /<!--- Start \/ Domain Info --->(.+?)<!--- End \/ Domain Info --->/is) {
            $resp = $1;
            $resp =~ s|</?table.*?>||ig;
            $resp =~ s|</?b>||ig;
            $resp =~ s|</?font.*?>||ig;
            $resp =~ s|<tr.*?>\s*<td.*?>\s*(.*?)\s*</td>\s*<td.*?>\s*(.*?)\s*</td>\s*</tr>|$1 $2\n|isg;
            $resp =~ s|</?tr>||ig;
            $resp =~ s|</?td>||ig;
            $resp =~ s|^\s*||mg;
        }
	else {
            return 0;
        }

    }
    elsif ($tld eq 'bz') {

	if ($resp =~ m|<pre>(.+?)</pre>|xms) {
	    $resp = $1;
	}

    }
    else {
        return 0;
    }
    
    return $resp;
}

# check, if it's IP-address?
sub is_ipaddr {
    $_[0] =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
}

# check, if it's IPv6-address?
sub is_ip6addr {
    # TODO: bad implementation!!!!!
    $_[0] =~ /:/;
}

# get domain level
sub domain_level {
    my ($str) = @_;
    
    my $dotcount = $str =~ tr/././;
    
    return $dotcount + 1;
}

# split domain on name and TLD
sub split_domain {
    my ($dom) = @_;

    my $tld = get_dom_tld( $dom );

    my $name;
    if (uc $tld eq 'IP' || $tld eq 'NOTLD') {
	$name = $dom;
    }
    else {
	$dom =~ /(.+?)\.$tld$/; # or die "Can't match $tld in $dom";
	$name = $1;
    }

    return ($name, $tld);
}

#
sub dlen {
    my ($str) = @_;

    return length($str) * domain_level($str);
}

# koi-8 to win-1251 encoding
sub koi2win($) {
    my $val = $_[0] or return;

    $val =~ tr/бвчздецъйклмнопртуфхжигюыэшщяьасБВЧЗДЕЦЪЙКЛМНОПРТУФХЖИГЮЫЭЯЩШЬАСіЈ/А-яЁё/;

    # ukr chars
    $val =~ tr/¤¦§ґ¶·Ѕ/єіїЄІЇҐ/;
    $val =~ s/\xAD/ґ/g;

    return $val;
}

1;

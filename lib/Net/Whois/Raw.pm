package Net::Whois::Raw;

require Net::Whois::Raw::Data;

use strict;

use Carp;
use IO::Socket;

our @EXPORT    = qw( whois get_whois );

our $VERSION = '1.33';

our ($OMIT_MSG, $CHECK_FAIL, $CHECK_EXCEED, $CACHE_DIR, $USE_CNAMES, $TIMEOUT, $DEBUG) = (0) x 7;
our $CACHE_TIME = 60;
our (%notfound, %strip, @SRC_IPS);

my $last_cache_clear_time;

sub whois_config {
    my ($par) = @_;
    my @parnames = qw(OMIT_MSG CHECK_FAIL CACHE_DIR CACHE_TIME USE_CNAMES TIMEOUT @SRC_IPS);
    foreach my $parname (@parnames) {
        if (exists($par->{$parname})) {
	    no strict 'refs';
            ${$parname} = $par->{$parname};
        }
    }
}

# get cached whois
sub whois {
    my ($dom) = @_;

    my $got_from_cache;

    my $res = get_from_cache( $dom );

    if ($res) {
        $got_from_cache = 1;
    } else {
        $res = get_whois(@_);
    }
    
    unless ($got_from_cache) {
        write_to_cache( $dom, $res );
    }

    return $res;
}

# obtain whois
sub get_whois {
    my ($dom, $srv, $which_whois) = @_;
    $which_whois ||= 'QRY_LAST';

    my $whois = get_all_whois($dom, $srv, $which_whois eq 'QRY_FIRST')
        or return undef;

    if ($which_whois eq 'QRY_LAST') {
	my $thewhois = $whois->[-1];
        return wantarray ? ($thewhois->{text}, $thewhois->{srv}) : $thewhois->{text};
    } elsif ($which_whois eq 'QRY_FIRST') {
	my $thewhois = $whois->[0];
        return wantarray ? ($thewhois->{text}, $thewhois->{srv}) : $thewhois->{text};
    } else {
        return $whois;
    }
}

sub get_from_cache {
    my ($dom) = @_;

    return undef unless $CACHE_DIR;

    mkdir $CACHE_DIR, 0755 unless -d $CACHE_DIR;

    my $now = time;
    if ($CACHE_TIME && (!$last_cache_clear_time || $last_cache_clear_time < $now - 60)) {
        # clear the cache
        foreach (glob("$CACHE_DIR/*.*")) {
            my $mtime = (stat($_))[8];
            my $elapsed = $now - $mtime;
            unlink $_ if ($elapsed / 60 > $CACHE_TIME); 
        }
	$last_cache_clear_time = time;
    }
        
    if (-f "$CACHE_DIR/$dom") {
        if (open(I, "$CACHE_DIR/$dom")) {
            my $res = join("", <I>);
            close(I);
            return $res;
        }
    }
}

sub write_to_cache {
    my ($dom, $whois) = @_;

    return unless $CACHE_DIR && $dom && $whois;

    if (open(O, ">$CACHE_DIR/$dom")) {
        print O $whois;
        close(O);
    }
}

sub get_all_whois {
    my ($dom, $srv, $norecurse) = @_;

    $srv ||= get_srv( $dom );

    if ($srv eq 'www_whois') {
	my ($responce, $ishtml) = www_whois_query( $dom );
	return $responce ? [ { text => $responce, srv => $srv } ] : $responce;
    }

    $dom =~ s/.NS$//i;

    my @whois = recursive_whois($dom, $srv, [], $norecurse);

    return process_whois_answers( \@whois, $dom );
}

sub get_srv {
    my ($dom) = @_;

    my $tld = uc get_dom_tld( $dom );
    $tld =~ s/^XN--(\w)/XN---$1/;

    if (grep { $_ eq $tld } @Net::Whois::Raw::Data::www_whois) {
	return 'www_whois';
    }

    my $cname = "$tld.whois-servers.net";

    my $srv = $Net::Whois::Raw::Data::servers{$tld} || $cname;
    $srv = $cname if $USE_CNAMES && gethostbyname($cname);

    return $srv;
}

sub get_dom_tld {
    my ($dom) = @_;

    my $tld;
    if (_is_ipaddr($dom)) {
        $tld = "IP";
    } elsif (_domain_level($dom) == 1) {
        $tld = "NOTLD";
    } else { 
        my @alltlds = keys %Net::Whois::Raw::Data::servers;
        @alltlds = sort { _dlen($b) <=> _dlen($a) } @alltlds;
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

sub split_domname {
    my ($dom) = @_;

    my $tld = get_dom_tld( $dom );

    my $name;
    if (uc $tld eq 'IP' || $tld eq 'NOTLD') {
	$name = $dom;
    } else {
	$dom =~ /(.+?)\.$tld$/ or die "Can't match $tld in $dom";
	$name = $1;
    }

    return ($name, $tld);
}

sub _is_ipaddr {
    $_[0] =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
}

sub process_whois_answers {
    my ($raw_whois, $dom) = @_;

    my @processed_whois;

    my $level = 0;
    foreach my $whois_rec (@{$raw_whois}) {
       $whois_rec->{level} = $level;
       my $text = process_whois( $whois_rec, $dom );
       if ($text) {
           $whois_rec->{text} = $text;
           push @processed_whois, $whois_rec;
       }
       $level++;
    }
    
    return \@processed_whois;
}

sub process_whois {
    my ($whois_rec, $dom) = @_;

    my $text = $whois_rec->{text};
    my $srv = lc $whois_rec->{srv};
    my $level = $whois_rec->{level} || 0;

    my ($name, $tld) = split_domname( $dom );

    if ($tld eq 'mu') {
	if ($text =~ /.MU Domain Information\n(.+?\n)\n/s) {
	    $text = $1;
	}
    }

    return $text unless $CHECK_FAIL || $OMIT_MSG || $CHECK_EXCEED;
    
    my $exceed = $Net::Whois::Raw::Data::exceed{$srv};
    if ($CHECK_EXCEED && $exceed && $text =~ /$exceed/s) {
	if ($level == 0) {
            die "Connection rate exceeded";
	} else {
	    return undef;
	}
    }

    *notfound = \%Net::Whois::Raw::Data::notfound;
    *strip = \%Net::Whois::Raw::Data::strip;

    my $notfound = $notfound{$srv};
    my @strip = $strip{$srv} ? @{$strip{$srv}} : ();
    my @lines;
    MAIN: foreach (split(/\n/, $text)) {
        if ($CHECK_FAIL && $notfound && /$notfound/) {
            return undef;
        };
        if ($OMIT_MSG) {
            foreach my $re (@strip) {
                next MAIN if (/$re/);
            }
        }
        push(@lines, $_);
    }

    local ($_) = join("\n", @lines, "");

    if ($CHECK_FAIL > 1) {
        return undef unless check_existance($_);
    }

    if ($OMIT_MSG > 1) {
    	$_ = strip_whois( $_ );        
    }
    $_;
}


sub recursive_whois {
    my ($dom, $srv, $was_srv, $norecurse) = @_;

    my $lines = whois_query( $dom, $srv );
    my $whois = join("", @{$lines});

    my ($newsrv, $registrar);
    foreach (@{$lines}) {
    	$registrar ||= /Registrar/ || /Registered through/;

    	if ( $registrar && !$norecurse && /Whois Server:\s*([A-Za-z0-9\-_\.]+)/ ) {
            $newsrv = lc $1;
    	} elsif ($whois =~ /To single out one record, look it up with \"xxx\",/s) {
            return recursive_whois( "=$dom", $srv, $was_srv );
	} elsif (/ReferralServer: whois:\/\/([-.\w]+)/) {
	    warn "SEX!!!!\n";
	    $newsrv = $1;
	    last;
	} elsif (/Contact information can be found in the (\S+)\s+database/) {
	    $newsrv = $Net::Whois::Raw::Data::ip_whois_servers{ $1 };
    	} elsif ((/OrgID:\s+(\w+)/ || /descr:\s+(\w+)/) && _is_ipaddr($dom)) {
	    my $val = $1;	
	    if($val =~ /^(?:RIPE|APNIC|KRNIC|LACNIC)$/) {
		$newsrv = $Net::Whois::Raw::Data::ip_whois_servers{ $val };
		last;
	    }
    	} elsif (/^\s+Maintainer:\s+RIPE\b/ && _is_ipaddr($dom)) {
            $newsrv = $Net::Whois::Raw::Data::servers{RIPE};
	}
    }

    my @whois_recs = ( { text => $whois, srv => $srv } );

    if ($newsrv && $newsrv ne $srv) {
        warn "recurse to $newsrv\n" if $DEBUG;
        return () if grep {$_ eq $newsrv} @$was_srv;
        my @new_whois_recs = eval { recursive_whois( $dom, $newsrv, [@$was_srv, $srv]) };
	my $new_whois = scalar(@new_whois_recs) ? $new_whois_recs[0]->{text} : '';
        if ($new_whois && !$@ && check_existance($new_whois)) {
            push @whois_recs, @new_whois_recs;
        } else {
    	    warn "recursive query failed\n" if $DEBUG;
	}
    }

    return @whois_recs;
}

sub whois_query {
    my ($dom, $srv) = @_;

    # Prepare query
    my $whoisquery = $dom;
    if ($srv eq 'whois.crsnic.net') {
        $whoisquery = "domain $whoisquery";
    }
    if ($srv eq 'whois.denic.de') {
        $whoisquery = "-T dn,ace -C ISO-8859-1 $whoisquery";
    }
    if ($srv eq 'whois.nic.name') {
        $whoisquery = "domain=$whoisquery";
    }

    # Prepare for query

    my @sockparams;
    if (scalar(@SRC_IPS)) {
        my $src_ip = $SRC_IPS[0];
        push @SRC_IPS, shift @SRC_IPS; # rotate ips
	@sockparams = (PeerAddr => "$srv:43", LocalAddr => $src_ip);
    } else {
	@sockparams = "$srv:43";
    }

    print "QUERY: $whoisquery; SRV: $srv, ".
	    "OMIT_MSG: $OMIT_MSG, CHECK_FAIL: $CHECK_FAIL, CACHE_DIR: $CACHE_DIR, ".
	    "CACHE_TIME: $CACHE_TIME, USE_CNAMES: $USE_CNAMES, TIMEOUT: $TIMEOUT\n" if $DEBUG >= 2;

    my $prev_alarm = 0;
    my @lines;

    # Make query

    eval {
        local $SIG{'ALRM'} = sub { die "Connection timeout to $srv" };
        $prev_alarm = alarm $TIMEOUT if $TIMEOUT;
	my $sock = new IO::Socket::INET(@sockparams) || Carp::confess "$srv: $!: ".join(', ', @sockparams);

	if ($DEBUG >= 2) {
	    _require_once('Data::Dumper');
	    print "Socket: ".Dumper($sock);
	}
	print $sock "$whoisquery\r\n";
	@lines = <$sock>;
	close $sock;
    };

    alarm $prev_alarm;
    die $@ if $@;

    foreach (@lines) { s/\r//g; }

    print "Received ".scalar(@lines)." lines\n" if $DEBUG >= 2;

    return \@lines;
}

sub www_whois_query {
    my ($dom) = (lc shift);

    my ($name, $tld) = split_domname( $dom );

    my ($url, $curl, %form);

    if ($tld eq 'tv') {
        $url = "http://www.tv/cgi-bin/whois.cgi?domain=$name&tld=tv";
    } elsif ($tld eq 'mu') {
        $url = 'http://www.mu/cgi-bin/mu_whois.cgi';
        $form{whois} = $name;
    } elsif ($tld eq 'spb.ru' || $tld eq 'msk.ru') {
        $url = "http://www.relcom.ru/Services/Whois/?fullName=$name.$tld";
    } elsif ($tld eq 'ru' || $tld eq 'su') {
        $url = "http://www.nic.ru/whois/?domain=$name.$tld";
    } elsif ($tld eq 'ip') {
        $url = "http://www.nic.ru/whois/?ip=$name";
    } elsif ($tld eq 'in') {
        $url = "http://www.registry.in/cgi-bin/whois.cgi?whois_query_field=$name";
    } elsif ($tld eq 'cn') {
        $url = "http://ewhois.cnnic.net.cn/whois?value=$name.$tld&entity=domain";
    } elsif ($tld eq 'ws') {
	$url = "http://worldsite.ws/utilities/lookup.dhtml?domain=$name&tld=$tld";
    } elsif ($tld eq 'kz') {
	$url = "http://www.nic.kz/cgi-bin/whois?query=$name.$tld&x=0&y=0";
    } else {
        return 0;
    }

    # load-on-demand
    unless ($INC{'LWP/UserAgent.pm'}) {
	require LWP::UserAgent;
	require HTTP::Request;
	require URI::URL;
	import LWP::UserAgent;
	import HTTP::Request;
	import URI::URL;
    }

    my $method = scalar(keys %form) ? 'POST' : 'GET';

    my $ua = new LWP::UserAgent( parse_head => 0 );
    my $req = new HTTP::Request $method, $url;

    if ($method eq 'POST') {
        $curl = url("http:");
        $req->content_type('application/x-www-form-urlencoded');
        $curl->query_form( %form );
        $req->content( $curl->equery );
    }

    my $resp = eval {
        local $SIG{ALRM} = sub { die "www_whois connection timeout" };
        alarm 10;
        $ua->request($req)->content;
    };
    alarm 0;
    return undef if !$resp || $@ || $resp =~ /www_whois connection timeout/;

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

    } elsif ($tld eq 'spb.ru' || $tld eq 'msk.ru') {

        $resp = _koi2win( $resp );
        return undef unless $resp =~ m|<TABLE BORDER="0" CELLSPACING="0" CELLPADDING="2"><TR><TD BGCOLOR="#990000"><TABLE BORDER="0" CELLSPACING="0" CELLPADDING="20"><TR><TD BGCOLOR="white">(.+?)</TD></TR></TABLE></TD></TR></TABLE>|s;
        $resp = $1;

        return 0 if $resp =~ m/СВОБОДНО/;

        if ($resp =~ m|<PRE>(.+?)</PRE>|s) {
            $resp = $1;
        } elsif ($resp =~ m|DNS \(name-серверах\):</H3><BLOCKQUOTE>(.+?)</BLOCKQUOTE><H3>Дополнительную информацию можно получить по адресу:</H3><BLOCKQUOTE>(.+?)</BLOCKQUOTE>|) {
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

    } elsif ($tld eq 'mu') {

        return 0 unless
        $resp =~ /(<p><b>Domain Name:<\/b><br>.+?)<hr width="75%">/s;
        $resp = $1;
        $ishtml = 1;

    } elsif ($tld eq 'ru' || $tld eq 'su') {

        $resp = _koi2win($resp);
        (undef, $resp) = split('<script>.*?</script>',$resp);
        ($resp) = split('</td></tr></table>', $resp);
        $resp =~ s/&nbsp;/ /gi;
        $resp =~ s/<([^>]|\n)*>//gi;

        return 0 if ($resp=~ m/Доменное имя .*? не зарегистрировано/i);
        $resp = 'ERROR' if $resp =~ m/Error:/i || $resp !~ m/Информация о домене .+? \(по данным WHOIS.RIPN.NET\):/;;

    } elsif ($tld eq 'ip') {

        unless ($resp =~ m|<p ID="whois">(.+?)</p>|s) {
            return 0;
        }

        $resp = $1;
        
        $resp =~ s|<a.+?>||g;
        $resp =~ s|</a>||g;
        $resp =~ s|<br>||g;
        $resp =~ s|&nbsp;| |g;

    } elsif ($tld eq 'in') {

        if ($resp =~ /Domain ID:\w{3,10}-\w{4}\n(.+?)\n\n/s) {
            $resp = $1;
            $resp =~ s/<br>//g;
        } else {
            return 0;
        }

    } elsif ($tld eq 'cn') {

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
        } else {
            return 0;
        }

    } elsif ($tld eq 'ws') {

	if ($resp =~ /Whois information for .+?:(.+?)<table>/s) {
	    $resp = $1;
            $resp =~ s|<font.+?>||isg;
            $resp =~ s|</font>||isg;

            $ishtml = 1;
	} else {
	    return 0;
	}

    } elsif ($tld eq 'kz') {
    
	if ($resp =~ /Domain Name\.{10}/s && $resp =~ /<pre>(.+?)<\/pre>/s) {
	    $resp = $1;
	} else {
	    return 0;
	}

    } else {
        return 'ERROR';
    }

    return wantarray ? ($resp, $ishtml) : $resp;
}

sub _domain_level {
    my ($str) = @_;
    my $dotcount = $str =~ tr/././;
    return $dotcount + 1;
}

sub _dlen {
    my ($str) = @_;
    return length($str) * _domain_level($str);
}


sub check_existance {
    $_ = $_[0];

    return undef if
        /is unavailable/is ||
        /No entries found for the selected source/is ||
        /Not found:/s ||
        /No match\./s ||
        /is available for/is ||
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
    s/TERMS OF USE:.*?modify these terms at any time\.//s;
    s/NOTICE:.*for this registration\.//s;

    s/By submitting a WHOIS query.+?DOMAIN AVAILABILITY.\n?//s;
    s/Registration and WHOIS.+?its accuracy.\n?//s;
    s/Disclaimer:.+?\*\*\*\n?//s;
    s/The .COOP Registration .+ Information\.//s;
    s/Whois Server Version \d+\.\d+.//is;
    s/NeuStar,.+www.whois.us\.//is;
    s/\n?Domain names in the \.com, .+ detailed information.\n?//s;
    s/\n?The Registry database .+?Registrars\.\n//s;
    s/\n?>>> Last update of .+? <<<\n?//;
    s/% .+?\n//gs;
    s/Domain names can now be registered.+?for detailed information.//s;

    s/^\n+//s;
    s/(?:\s*\n)+$/\n/s;

    $_;
}

# charset / conversion functions

sub _koi2win($) {
    my $val = $_[0];
    $val =~ tr/бвчздецъйклмнопртуфхжигюыэшщяьасБВЧЗДЕЦЪЙКЛМНОПРТУФХЖИГЮЫЭЯЩШЬАСіЈ/А-яЁё/;
    return $val;
}

sub _require_once ($) {
    my ($module) = @_;

    my $module_file = $module.'.pm';
    $module_file =~ s/::/\//g;

    unless ($INC{$module_file}) {
	eval "require $module";
	import $module;
    }
}

sub import {
    my $mypkg = shift;
    my $callpkg = caller;

    no strict 'refs';

    # export subs
    *{"$callpkg\::$_"} = \&{"$mypkg\::$_"} foreach ((@EXPORT, @_));
}

1;
__END__

=head1 NAME

Net::Whois::Raw - Get Whois information for domains

=head1 SYNOPSIS

  use Net::Whois::Raw;
  
  $dominfo = whois('perl.com');
  $dominfo = whois('funet.fi');
  $reginfo = whois('REGRU-REG-RIPN', 'whois.ripn.net');

  $arrayref = get_whois('yahoo.co.uk', undef, 'QRY_ALL');
  $text = get_whois('yahoo.co.uk', undef, 'QRY_LAST');
  ($text, $srv) = get_whois('yahoo.co.uk', undef, 'QRY_FIRST');

  ### if you do "use Net::Whois::Raw qw(
  #     $OMIT_MSG $CHECK_FAIL $CHECK_EXCEED
  #     $CACHE_DIR $CACHE_TIME $USE_CNAMES $TIMEOUT @SRC_IPS );
  ### you can use these:

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

  $CHECK_EXCEED = 1; # When this option is set, "die" will be called
                if connection rate to specific whois server have been
                exceeded

  $CACHE_DIR = "/var/spool/pwhois/"; # Whois information will be
                cached in this directory. Default is no cache.

  $CACHE_TIME = 60; # Cache files will be cleared after not accessed
                for a specific number of minutes. Documents will not be
                cleared if they keep get requested for, independent
                of disk space. Default is not to clear the cache.

  $USE_CNAMES = 1; # Use whois-servers.net to get the whois server
                name when possible. Default is to use the 
                hardcoded defaults.


  $TIMEOUT = 10; # Cancel the request if connection is not made within
                a specific number of seconds.

  @SRC_IPS = (11.22.33.44); # List of local IP addresses to
		use for WHOIS queries. Addresses will be used used
		successively in the successive queries

=head1 DESCRIPTION

Net::Whois::Raw queries WHOIS servers about domains.
The module supports recursive WHOIS queries.
Also queries via HTTP is supported for some TLDs.

Setting the variables $OMIT_MSG and $CHECK_FAIL will match the results
against a set of known patterns. The first flag will try to omit the
copyright message/disclaimer, the second will attempt to determine if
the search failed and return undef in such a case.

B<IMPORTANT>: these checks merely use pattern matching; they will work
on several servers but certainly not on all of them.

=head1 FUNCTIONS

=over 3

=item whois( DOMAIN [, SRV [, WHICH_WHOIS]] )

Returns Whois information for C<DOMAIN>.
Without C<SRV> argument default Whois server for specified domain name
zone will be used. Use 'www_whois' as server name to force
WHOIS querying via HTTP (only few TLDs are supported in HTTP queries).
Caching is supported: if $CACHE_DIR variable is set and there is cached
entry for that domain - information from the cache will be used.
C<WHICH_WHOIS> argument - look get_whois docs below.

=item get_whois( DOMAIN [, SRV [, WHICH_WHOIS]] )

Lower-level function to query Whois information for C<DOMAIN>.
Caching IS NOT supported (caching is implemented only in higher-level
C<whois> function).
Without C<SRV> argument default Whois server for specified domain name
zone will be used.
C<WHICH_WHOIS> argument is used to access a results if recursive queries;
possible values:

C<'QRY_FIRST'> -
    returns results of the first query. Non't make recursive queries.
    In scalar context returns just whois text.
    In list context returns two values: whois text and whois server
    which was used to make query).

C<'QRY_LAST'> -
    returns results of the last query.
    In scalar context returns just whois text.
    In list context returns two values: whois text and whois server
    which was used to make query).
    This is the default option.

C<'QRY_ALL'> -
    returns results of the all queries of the recursive chain.
    Reference to array of references to hashes is returned.
    Hash keys: C<text> - result of whois query, C<srv> -
    whois server which was used to make query.

=back

=head1 AUTHOR

Original author Ariel Brosh B<schop@cpan.org>, 
Inspired by jwhois.pl available on the net.

Since Ariel has passed away in September 2002:

Past maintainers Gabor Szabo B<gabor@perl.org.il>,
Corris Randall B<corris@cpan.org>

Current Maintainer: Walery Studennikov B<despair@cpan.org>

=head1 CREDITS

See file "Changes" in the distribution for the complete list of contributors.

=head1 CHANGES

See file "Changes" in the distribution

=head1 NOTE

Some users complained that the B<die> statements in the module make their
CGI scripts crash. Please consult the entries on B<eval> and
B<die> on L<perlfunc> about exception handling in Perl.

=head1 COPYRIGHT

Copyright 2000-2002 Ariel Brosh.
Copyright 2003-2003 Gabor Szabo.
Copyright 2003-2003 Corris Randall.
Copyright 2003-2006 Walery Studennikov.

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

L<pwhois>, L<whois>.

=cut

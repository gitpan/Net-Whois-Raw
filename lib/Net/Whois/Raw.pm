package Net::Whois::Raw;

require Net::Whois::Raw::Data;

use strict;
use vars qw(
    $VERSION $DEBUG @ISA @EXPORT @EXPORT_OK %EXPORT_TAGS
    $OMIT_MSG $CHECK_FAIL $CHECK_EXCEED
    %notfound %strip $CACHE_DIR $CACHE_TIME $USE_CNAMES $TIMEOUT
    @SRC_IPS
);
use IO::Socket;

require Exporter;

@ISA = qw(Exporter);

@EXPORT    = qw( whois get_whois );
@EXPORT_OK = qw(
    $OMIT_MSG $CHECK_FAIL $CHECK_EXCEED $CACHE_DIR $CACHE_TIME $USE_CNAMES $TIMEOUT
    @SRC_IPS whois_config
);

$VERSION = '0.91';

($OMIT_MSG, $CHECK_FAIL, $CHECK_EXCEED, $CACHE_DIR, $USE_CNAMES, $TIMEOUT) = (0) x 6;
$CACHE_TIME = 1;

my $last_cache_clear_time;

sub BEGIN {
    $DEBUG = 0;
    if ($DEBUG) {
	require Data::Dumper;
	import Data::Dumper;
    }
}

sub whois_config {
    my ($par) = @_;
    my @parnames = qw(OMIT_MSG CHECK_FAIL CACHE_DIR CACHE_TIME USE_CNAMES TIMEOUT @SRC_IPS);
    foreach my $parname (@parnames) {
        if (exists($par->{$parname})) {
            eval('$'.$parname.'='.int($par->{$parname}));
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

    mkdir $CACHE_DIR, 0755;

    my $now = time;
    if ($CACHE_TIME && (!$last_cache_clear_time || $last_cache_clear_time < $now - 1000)) {
        # clear the cache
        foreach (glob("$CACHE_DIR/*.*")) {
            my $mtime = (stat($_))[8];
            my $elapsed = $now - $mtime;
            unlink $_ if ($elapsed / 3600 > $CACHE_TIME); 
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

    $dom =~ s/.NS$//i;

    my @whois = recursive_whois($dom, $srv, [], $norecurse);

    return process_whois_answers( \@whois );
}

sub get_srv {
    my ($dom) = @_;

    my $tld = get_dom_tld( $dom );

    my $cname = "$tld.whois-servers.net";

    my $srv = $Net::Whois::Raw::Data::servers{uc $tld} || $cname;
    $srv = $cname if $USE_CNAMES && gethostbyname($cname);

    return $srv;
}

sub get_dom_tld {
    my ($dom) = @_;

    my $tld;
    if (is_ipaddr($dom)) {
        $tld = "IP";
    } else { 
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

sub is_ipaddr {
    $_[0] =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
}

sub process_whois_answers {
    my ($raw_whois) = @_;

    my @processed_whois;

    my $level = 0;
    foreach my $whois_rec (@{$raw_whois}) {
       $whois_rec->{level} = $level;
       my $text = process_whois( $whois_rec );
       if ($text) {
           $whois_rec->{text} = $text;
           push @processed_whois, $whois_rec;
       }
       $level++;
    }
    
    return \@processed_whois;
}

sub process_whois {
    my ($whois_rec) = @_;

    my $text = $whois_rec->{text};
    my $srv = lc $whois_rec->{srv};
    my $level = $whois_rec->{level} || 0;

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
    my $whois = $_ = join("", @{$lines});

    my ($newsrv, $registrar);
    foreach (@{$lines}) {
    	$registrar ||= /Registrar/ || /Registered through/;

    	if ( $registrar && !$norecurse && /Whois Server:\s*([A-Za-z0-9\-_\.]+)/ ) {
            $newsrv = lc $1;
    	} elsif (/^\s+Maintainer:\s+RIPE\b/ && is_ipaddr($dom)) {
            $newsrv = lc $Net::Whois::Raw::Data::servers{'RIPE'};
    	} elsif ($whois =~ /To single out one record, look it up with \"xxx\",/s) {
            return recursive_whois( "=$dom", $srv, $was_srv );
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

    my $sock;
    eval {
        local $SIG{'ALRM'} = sub { die "Connection timeout to $srv" };
        alarm $TIMEOUT if $TIMEOUT;
        if (scalar(@SRC_IPS)) {
            my $src_ip = $SRC_IPS[0];
            push @SRC_IPS, shift @SRC_IPS; # rotate ips
            $sock = new IO::Socket::INET(PeerAddr => "$srv:43", LocalAddr => $src_ip) || die "$srv: $!";
        } else {
            $sock = new IO::Socket::INET("$srv:43") || die "$srv: $!";
        }
    };
    alarm 0;
    die $@ if $@;
    my $israce = $dom =~ /ra--/ || $dom =~ /bq--/;
    my $whoisquery = $dom;
    if ($srv eq 'whois.crsnic.net') {
        $whoisquery = "domain $whoisquery";
    }
    if ($srv eq 'whois.melbourneit.com' && $israce) {
        $whoisquery .= ' race';
    }
    #warn "$srv: $whoisquery ($OMIT_MSG, $CHECK_FAIL, $CACHE_DIR, $CACHE_TIME, $USE_CNAMES, $TIMEOUT)\n";
    print $sock "$whoisquery\r\n";
    my @lines = <$sock>;
    close($sock);

    foreach (@lines) { s/\r//g; }

    return \@lines;
}

sub dlen {
    my ($str) = @_;
    my $dotcount = $str =~ tr/././;
    return length($str) * (1 + $dotcount);
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


1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Net::Whois::Raw - Get Whois information for domains

=head1 SYNOPSIS

  use Net::Whois::Raw;
  
  $s = whois('perl.com');
  $s = whois('funet.fi');

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

  $CACHE_TIME = 24; # Cache files will be cleared after not accessed
                for a specific number of hours. Documents will not be
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
The module supportts recursive WHOIS queries.

Setting the variables $OMIT_MSG and $CHECK_FAIL will match the results
against a set of known patterns. The first flag will try to omit the
copyright message/disclaimer, the second will attempt to determine if
the search failed and return undef in such a case.

B<IMPORTANT>: these checks merely use pattern matching; they will work
on several servers but certainly not on all of them.

=head1 FUNCTIONS

=over 3

=item whois( DOMAIN [, SRV] )

Returns Whois information for C<DOMAIN>.
Without C<SRV> argument default Whois server for specified domain name
zone will be used.
Caching is supported: if $CACHE_DIR variable is set and there is cached
entry for that domain - information from the cache will be used.

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

Original author Ariel Brosh, B<schop@cpan.org>, 
Inspired by jwhois.pl available on the net.

Since Ariel has passed away in September 2002:

Past maintainers Gabor Szabo, B<gabor@perl.org.il>,
Corris Randall B<corris@cpan.org>

Current Maintainer: Walery Studennikov B<despair@cpan.org>

=head1 CREDITS

Fixed regular expression to match hyphens. (Peter Chow,
B<peter@interq.or.jp>)

Added support for Tonga TLD. (.to) (Peter Chow, B<peter@interq.or.jp>)

Added support for reverse lookup of IP addresses via the ARIN registry. (Alex Withers B<awithers@gonzaga.edu>)

This will work now for RIPE addresses as well, according to a redirection from ARIN. (Philip Hands B<phil@uk.alcove.com>, Trevor Peirce B<trev@digitalcon.ca>)

Added the pattern matching switches, (Walery Studennikov B<despair@cpan.org>)

Modified pattern matching, added cache. (Tony L. Svanstrom B<tony@svanstrom.org>)

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
Copyright 2003-2004 Walery Studennikov.

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

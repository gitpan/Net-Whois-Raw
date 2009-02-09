package Net::Whois::Raw;

require Net::Whois::Raw::Common;
require Net::Whois::Raw::Data;

use strict;

use Carp;
use IO::Socket;

our @EXPORT = qw( whois get_whois );

our $VERSION = '1.63';

our ($OMIT_MSG, $CHECK_FAIL, $CHECK_EXCEED, $CACHE_DIR, $USE_CNAMES, $TIMEOUT, $DEBUG) = (0) x 7;
our $CACHE_TIME = 60;
our (%notfound, %strip, @SRC_IPS, %POSTPROCESS);

our $class = __PACKAGE__;

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
    my ($dom, $server, $which_whois) = @_;

    $which_whois ||= 'QRY_LAST';

    my $res = Net::Whois::Raw::Common::get_from_cache(
        $dom, $CACHE_DIR, $CACHE_TIME
    );

    if ($res) {
        if ($which_whois eq 'QRY_FIRST') {
            $res = $res->[0]->{text};
        } elsif ($which_whois eq 'QRY_LAST' || !defined($which_whois)) {
            $res = $res->[-1]->{text};
        }
    }
    else {
        $res = get_whois($dom, $server, $which_whois);
    }
    
    return $res;
}

# obtain whois
sub get_whois {
    my ($dom, $srv, $which_whois) = @_;
    $which_whois ||= 'QRY_LAST';

    my $whois = get_all_whois($dom, $srv, $which_whois eq 'QRY_FIRST')
        or return undef;

    Net::Whois::Raw::Common::write_to_cache($dom, $whois, $CACHE_DIR);
    
    if ($which_whois eq 'QRY_LAST') {
	my $thewhois = $whois->[-1];
        return wantarray ? ($thewhois->{text}, $thewhois->{srv}) : $thewhois->{text};
    }
    elsif ($which_whois eq 'QRY_FIRST') {
	my $thewhois = $whois->[0];
        return wantarray ? ($thewhois->{text}, $thewhois->{srv}) : $thewhois->{text};
    }
    else {
        return $whois;
    }
}

sub get_all_whois {
    my ($dom, $srv, $norecurse) = @_;

    $srv ||= Net::Whois::Raw::Common::get_server( $dom, $USE_CNAMES );

    if ($srv eq 'www_whois') {
	my ($responce, $ishtml) = www_whois_query( $dom );
	return $responce ? [ { text => $responce, srv => $srv } ] : $responce;
    }

    my $is_ns = 0;
    $is_ns = 1 if $dom =~ s/.NS$//i;

    my @whois = recursive_whois( $dom, $srv, [], $norecurse, $is_ns );

    return process_whois_answers( \@whois, $dom );
}

sub process_whois_answers {
    my ($raw_whois, $dom) = @_;

    my @processed_whois;

    my $level = 0;
    foreach my $whois_rec (@{$raw_whois}) {
        $whois_rec->{level} = $level;
        my ($text, $error) = Net::Whois::Raw::Common::process_whois(
            $dom,
            $whois_rec->{srv},
            $whois_rec->{text},
            $CHECK_FAIL, $OMIT_MSG, $CHECK_EXCEED,
        );
        die $error if $level == 0 && $error && $error eq "Connection rate exceeded";
        if ($text || $level == 0) {
            $whois_rec->{text} = $text;
            push @processed_whois, $whois_rec;
        }
        $level++;
    }
    
    return \@processed_whois;
}

sub recursive_whois {
    my ($dom, $srv, $was_srv, $norecurse, $is_ns) = @_;

    my $lines = whois_query( $dom, $srv, $is_ns );
    my $whois = join("", @{$lines});

    my ($newsrv, $registrar);
    foreach (@{$lines}) {
    	$registrar ||= /Registrar/ || /Registered through/;

    	if ( $registrar && !$norecurse && /Whois Server:\s*([A-Za-z0-9\-_\.]+)/ ) {
            $newsrv = lc $1;
    	}
	elsif ($whois =~ /To single out one record, look it up with \"xxx\",/s) {
            return recursive_whois( "=$dom", $srv, $was_srv );
	}
	elsif (/ReferralServer: whois:\/\/([-.\w]+)/) {
	    $newsrv = $1;
	    last;
	}
	elsif (/Contact information can be found in the (\S+)\s+database/) {
	    $newsrv = $Net::Whois::Raw::Data::ip_whois_servers{ $1 };
    	}
	elsif ((/OrgID:\s+(\w+)/ || /descr:\s+(\w+)/) && Net::Whois::Raw::Common::is_ipaddr($dom)) {
	    my $val = $1;	
	    if($val =~ /^(?:RIPE|APNIC|KRNIC|LACNIC)$/) {
		$newsrv = $Net::Whois::Raw::Data::ip_whois_servers{ $val };
		last;
	    }
    	}
	elsif (/^\s+Maintainer:\s+RIPE\b/ && Net::Whois::Raw::Common::is_ipaddr($dom)) {
            $newsrv = $Net::Whois::Raw::Data::servers{RIPE};
	}
	elsif ( $is_ns && $srv eq $Net::Whois::Raw::Data::servers{NS} && /No match for nameserver/ && $dom =~ /.name$/i ) {
	    $newsrv = $Net::Whois::Raw::Data::servers{NAME};
	}
    }

    my @whois_recs = ( { text => $whois, srv => $srv } );

    if ($newsrv && $newsrv ne $srv) {
        warn "recurse to $newsrv\n" if $DEBUG;

        return () if grep {$_ eq $newsrv} @$was_srv;
        my @new_whois_recs = eval { recursive_whois( $dom, $newsrv, [@$was_srv, $srv], 0, $is_ns) };
	my $new_whois = scalar(@new_whois_recs) ? $new_whois_recs[0]->{text} : '';
        if ($new_whois && !$@ && Net::Whois::Raw::Common::check_existance($new_whois)) {
            if ( $is_ns ) {
                unshift @whois_recs, @new_whois_recs;
            }
            else {
                push @whois_recs, @new_whois_recs;
            }
        }
	else {
    	    warn "recursive query failed\n" if $DEBUG;
	}
    }

    return @whois_recs;
}

sub whois_query {
    my ($dom, $srv, $is_ns) = @_;

    # Prepare query
    my $whoisquery = Net::Whois::Raw::Common::get_real_whois_query($dom, $srv, $is_ns);

    # Prepare for query

    my @sockparams;
    if ($class->can ('whois_query_sockparams')) {
        @sockparams = $class->whois_query_sockparams ($dom, $srv);
    }
    elsif (scalar(@SRC_IPS)) {
        my $src_ip = $SRC_IPS[0];
        push @SRC_IPS, shift @SRC_IPS; # rotate ips
        @sockparams = (PeerAddr => "$srv:43", LocalAddr => $src_ip);
    }
    else {
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
        my $sock = IO::Socket::INET->new(@sockparams) || Carp::confess "$srv: $!: ".join(', ', @sockparams);
        
        if ($class->can ('whois_socket_fixup')) {
            my $new_sock = $class->whois_socket_fixup ($sock);
	    $sock = $new_sock if $new_sock;
        }

	if ($DEBUG > 2) {
	    _require_once('Data::Dumper');
	    print "Socket: ".Dumper($sock);
	}

        $sock->print( $whoisquery, "\r\n" );
        # TODO: $soc->read, parameters for read chunk size, max content length
        while (my $str = <$sock>) {
            push @lines, $str;
        }
        $sock->close;
    };

    alarm $prev_alarm;
    die $@ if $@;

    foreach (@lines) { s/\r//g; }

    print "Received ".scalar(@lines)." lines\n" if $DEBUG >= 2;

    return \@lines;
}

sub www_whois_query {
    my ($dom) = (lc shift);

    my ($name, $tld) = Net::Whois::Raw::Common::split_domain( $dom );
    my ($url, %form) = Net::Whois::Raw::Common::get_http_query_url($dom);
    
    # load-on-demand
    unless ($INC{'LWP/UserAgent.pm'}) {
	require LWP::UserAgent;
	require HTTP::Request;
	require HTTP::Headers;
	require URI::URL;
	import LWP::UserAgent;
	import HTTP::Request;
	import HTTP::Headers;
	import URI::URL;
    }
    
    my $referer = delete $form{referer} if %form && $form{referer};
    my $method = scalar(keys %form) ? 'POST' : 'GET';

    my $ua = new LWP::UserAgent( parse_head => 0 );
    $ua->agent('Mozilla/5.0 (X11; U; Linux i686; ru; rv:1.9.0.5) Gecko/2008121622 Fedora/3.0.5-1.fc10 Firefox/3.0.5');
    my $header = HTTP::Headers->new;
    $header->header('Referer' => $referer) if $referer;
    my $req = new HTTP::Request $method, $url, $header;

    if ($method eq 'POST') {
        require URI::URL;
        import URI::URL;

        my $curl = url("http:");
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

    $resp = Net::Whois::Raw::Common::parse_www_content($resp, $tld, $CHECK_EXCEED);

    return wantarray ? ($resp, $ishtml) : $resp;
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

  $Net::Whois::Raw::OMIT_MSG = 1;
	# This will attempt to strip several known copyright
        # messages and disclaimers sorted by servers.
        # Default is to give the whole response.

  $Net::Whois::Raw::OMIT_MSG = 2;
	# This will try some additional stripping rules
        # if none are known for the spcific server.

  $Net::Whois::Raw::CHECK_FAIL = 1;
	# This will return undef if the response matches
        # one of the known patterns for a failed search,
        # sorted by servers.
        # Default is to give the textual response.

  $Net::Whois::Raw::CHECK_FAIL = 2;
	# This will match against several more rules
        # if none are known for the specific server.

  $Net::Whois::Raw::CHECK_EXCEED = 1;
	# When this option is set, "die" will be called
        # if connection rate to specific whois server have been
        # exceeded

  $Net::Whois::Raw::CACHE_DIR = "/var/spool/pwhois/";
	# Whois information will be
        # cached in this directory. Default is no cache.

  $Net::Whois::Raw::CACHE_TIME = 60;
	# Cache files will be cleared after not accessed
        # for a specific number of minutes. Documents will not be
        # cleared if they keep get requested for, independent
        # of disk space. Default is not to clear the cache.

  $Net::Whois::Raw::USE_CNAMES = 1;
	# Use whois-servers.net to get the whois server
        # name when possible. Default is to use the 
        # hardcoded defaults.

  $Net::Whois::Raw::TIMEOUT = 10;
	# Cancel the request if connection is not made within
        # a specific number of seconds.

  @Net::Whois::Raw::SRC_IPS = (11.22.33.44);
	# List of local IP addresses to
	# use for WHOIS queries. Addresses will be used used
	# successively in the successive queries

  $Net::Whois::Raw::POSTPROCESS{whois.crsnic.net} = \&my_func;
        # Call to a user-defined subroutine on whois result,
        # depending on whois-server.
        # Above is equil to:
        # ($text, $srv) = whois('example.com');
        # $text = my_func($text) if $srv eq 'whois.crsnic.net';

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

Copyright 2000--2002 Ariel Brosh.
Copyright 2003--2003 Gabor Szabo.
Copyright 2003--2003 Corris Randall.
Copyright 2003--now() Walery Studennikov.

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

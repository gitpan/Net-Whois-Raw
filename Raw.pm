package Net::Whois::Raw;

use strict;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK %servers);

use IO::Socket;

require Exporter;

@ISA = qw(Exporter);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw(
whois	
);
$VERSION = '0.10';

%servers = qw(COM whois.networksolutions.com
	 NET whois.networksolutions.com
	 EDU whois.networksolutions.com
	 ORG whois.networksolutions.com
	 ARPA whois.arin.net
	 MIL whois.nic.mil
	 TO whois.tonic.to);

sub whois {
    my $dom = shift;
    my @tokens = split(/\./, $dom);
    my $tld = uc($tokens[-1]);
    my $srv = $servers{$tld} || "$tld.whois-servers.net";
    my $flag = ($srv eq 'whois.networksolutions.com');
    _whois($dom, uc($srv), $flag, []);
}

sub _whois {
    my ($dom, $srv, $flag, $ary) = @_;
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

=head1 DESCRIPTION

Net::Whois::Raw queries NetworkSolutions and follows the Registrar: answer
for ORG, EDU, COM and NET domains.
For other TLDs it uses the whois-servers.net namespace.
(B<$TLD>.whois-servers.net).

=head1 AUTHOR

Ariel Brosh, B<schop@cpan.org>, Inspired by jwhois.pl available on the
net.

Peter Chow, B<peter@interq.or.jp>, Corrections. (See below)

=head1 MODIFICATIONS

=item

Fixed regular expression to match hyphens. (Peter Chow,
B<peter@interq.or.jp>)

=item

Added support for Tonga TLD. (.to) (Peter Chow, B<peter@interq.or.jp>)

=head1 CLARIFICATION

As NetworkSolutions got most of the domains of InterNic as legacy, we
start by querying their server, as this way one whois query would be
sufficient for many domains. Starting at whois.internic.net or
whois.crsnic.net will result in always two requests in any case.

=head1 SEE ALSO

L<perl(1)>, L<Net::Whois>.

=cut

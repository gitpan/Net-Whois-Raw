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
$VERSION = '0.01';

%servers = qw(COM whois.networksolutions.com
	 NET whois.networksolutions.com
	 EDU whois.networksolutions.com
	 ORG whois.networksolutions.com
	 ARPA whois.arin.net
	 MIL whois.nic.mil);

sub whois {
    my $dom = shift;
    my @tokens = split(/\./, $dom);
    my $tld = uc($tokens[-1]);
    my $def = $servers{$tld};
    my $srv = $def ? $def : "$tld.whois-servers.net";
    my $flag = ($def eq 'whois.networksolutions.com');
    _whois($dom, uc($srv), $flag, []);
}

sub _whois {
    my ($dom, $srv, $flag, $ary) = @_;
    my $sock = new IO::Socket::INET("$srv:43") || die $!;
    print $sock "$dom\n";
    my @lines = <$sock>;
    close($sock);
    if ($flag) {
        foreach (@lines) {
            if (/^\s*Registrar: ([A-Za-z0-9_\.]+)/) {
                my $newsrv = uc($1);
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

=head1 SEE ALSO

L<perl(1)>, L<Net::Whois>.

=cut

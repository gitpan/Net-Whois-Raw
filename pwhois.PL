my $script = <<'END_OF_SCRIPT';
~startperl~

use Net::Whois::Raw;
use Getopt::Std;
use strict;
use vars qw($opt_s $opt_c);

getopts("sc");

$OMIT_MSG = $opt_s;
$CHECK_FAIL = $opt_c;

my $dom = $ARGV[0] || die "Usage: $0 domain";

my $server = $ARGV[1];

unless ($server) {
	print whois($dom);
} else {
	print Net::Whois::Raw::_whois($dom, $server);
}

__END__

=head1 NAME

pwhois   - Perl written whois client

=head1 SYNOPSIS

pwhois perl.com
pwhois gnu.org
pwhois -s police.co.il
pwhois -c there.is.no.tld.called.foobar
pwhois yahoo.com whois.networksolutions.com

etc etc.....

=head1 DESCRIPTION

Just invoke with a domain name, optionally with a whois server name.
The -s switch attempts to strip the copyright message or disclaimer.
The -c switch attempts to return an empty answer for failed searches.
 
=head1 AUTHOR

Ariel Brosh, B<schop@cpan.org>

=head1 SEE ALSO

L<Net::Whois::Raw>.

END_OF_SCRIPT
use Config;

my $file = __FILE__; $file =~ s/\.PL$//;

$script =~ s/\~(\w+)\~/$Config{$1}/eg;
if (!(open(FILE, ">$file"))  ||
    !(print FILE $script)  ||
    !(close(FILE))) {
    die "Error while writing $file: $!\n";
}
chmod 0755, $file;
print "Extracted $file from ",__FILE__," with variable substitutions.\n";


my $script = <<'END_OF_SCRIPT';
~startperl~

use Net::Whois::Raw;

my $dom = $ARGV[0] || die "Usage: $0 domain";

print whois($dom);

__END__

=head1 NAME

pwhois   - Perl written whois client

=head1 SYNOPSIS

pwhois perl.com
pwhois gnu.org
pwhois police.co.il

etc etc.....

=head1 DESCRIPTION

Just invoke with a domain name.
Does not support explicit domain name specifying.
 
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
print "Extracted $file from ",__FILE__," with variable substitutions.\n";


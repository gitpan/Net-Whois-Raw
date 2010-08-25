#!/usr/bin/perl -w
use strict;
use Module::Build;

my $build = Module::Build->new(
    module_name => 'Net::Whois::Raw',
    license  => 'perl',
    requires => {
	'perl' => '5.008001',
	'Getopt::Long' => 2.0,
	'URI::URL' => 0,
	'LWP::UserAgent' => 0,
	'HTTP::Request' => 0,
	'HTTP::Headers' => 0,
	'Test::More' => 0,
	'Encode' => 0,
    },
    create_makefile_pl => 'traditional',
    script_files => 'pwhois',
);

$build->create_build_script;

# IS IT NECESSARY? (see belowe)
#
#sub MY::postamble {
#        package MY;
#        shift->SUPER::postamble . <<'MAKE';
#dist : README
#
#README : lib/Net/Whois/Raw.pm
#	@$(PERL) -MPod::Text -e "pod2text('$<');" > $@
#
#MAKE
#}

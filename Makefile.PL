use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'Net::Whois::Raw',
    'VERSION_FROM' => 'Raw.pm', # finds $VERSION
    'PREREQ_PM' => {'IO::Socket' => 1.0},
    'EXE_FILES' => ['pwhois']
);

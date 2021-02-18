use ExtUtils::MakeMaker;

use 5.010;

WriteMakefile
 ( NAME	 	=> 'XML::ExistDB'
 , VERSION	=> '1.00'
 , PREREQ_PM    =>
   { XML::Compile              => 1.50
   , XML::Compile::Cache       => 1.04
   , XML::Compile::RPC         => 0.18
   , Log::Report               => 0.26
   , Time::HiRes               => 0
   , LWP::UserAgent            => 0
   , MIME::Base64              => 0
   , Test::More                => 0.54
   }

 , EXE_FILES    => []
 , AUTHOR       => 'Mark Overmeer'
 , ABSTRACT     => 'ExistDB interface over XML-RPC'
 , LICENSE      => 'perl_5'

  , META_MERGE =>
      { 'meta-spec' => { version => 2 }
      , resources  =>
          { repository =>
              { type => 'git'
              , url  => 'https://github.com/markov2/perl5-XML-ExistDB.git'
              , web  => 'https://github.com/markov2/perl5-XML-ExistDB'
              }
          , homepage => 'http://perl.overmeer.net/CPAN/'
          , license  => [ 'http://dev.perl.org/licenses/' ]
          }
      }
 );

### used by oodist during production of distribution
sub MY::postamble { <<'__POSTAMBLE' }

# for DIST
EXTENDS		= ../XML-Compile:../XML-Compile-Cache:../XML-Compile-RPC
RAWDIR		= ../public_html/xml-existdb/raw
DISTDIR		= ../public_html/xml-existdb/source
LICENSE		= perl
SKIP_LINKS	= XML::LibXML

# for POD
FIRST_YEAR	= 2010
EMAIL		= markov@cpan.org
WEBSITE		= http://perl.overmeer.net/CPAN/
__POSTAMBLE

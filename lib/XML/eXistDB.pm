use warnings;
use strict;

package XML::eXistDB;
use base 'XML::Compile::Cache';

use Log::Report 'xml-existdb', syntax => 'SHORT';

use XML::eXistDB::Util;
use XML::Compile::Util  qw/pack_type type_of_node/;
use XML::LibXML::Simple qw/XMLin/;

my $coll_type = pack_type NS_COLLECTION_XCONF, 'collection';

=chapter NAME
 XML::eXistDB - handle the eXist pure XML database

=chapter SYNOPSIS
 # You want to talk to eXist via a protocol. Read that manpage
 use XML::eXistDB::RPC;
 my $db = XML::eXistDB::RPC->new(...);

=chapter DESCRIPTION
There are many database which support XML and Xquery. Quite a number of
them translate XML into tables and Xquery into SQL statements. The eXist
database however, is a pure XML/Xquery database.
Website: F<http://exist-db.org>

The C<XML::eXistDB> distribution contains the following modules:
=over 4
=item . C<XML::eXistDB> focuses on processing eXist (configuration) files
=item . C<XML::eXistDB::Util> contains convenience functions and constants
=item . C<XML::eXistDB::RPC> implements the large XML-RPC API to speak to an eXist daemon
=back

The "REST" API for eXist is very different from the XML-RPC API, so there
is no chance on a common base-class. The XML-RPC API is probably quite close
to the XML:DB standard, but for the moment, no attempts are made to unify
the implementation to facilitate different XML databases back-ends.

=chapter METHODS

=section Constructors

=c_method new OPTIONS

=default allow_undeclared <true>

=option  opts_readers []
=default opts_readers <sloppy ints and floats>

=cut

sub init($)
{   my ($self, $args) = @_;

    exists $args->{allow_undeclared}
        or $args->{allow_undeclared} = 1;

    $args->{any_element} ||= 'SLOPPY';   # query results are sloppy

    unshift @{$args->{opts_readers}}
       , sloppy_integers => 1, sloppy_floats => 1;

    $self->SUPER::init($args);

    (my $xsddir = __FILE__) =~ s,\.pm,/xsd-exist,;
    my @xsds    = glob "$xsddir/*.xsd";

    $self->prefixes(exist => NS_EXISTDB);
    $self->importDefinitions(\@xsds);
    $self;
}

=section Collection configuration (.xconf)

=method createCollectionConfig DATA, OPTIONS
The DATA structure should provide the needs for an collection configuration
file, in the shape C<XML::Compile> expects based on the schema. See the
C<template/collection.xconf>, which is part of the distribution.

=option  beautify BOOLEAN
=default beautify <true>
=cut

sub createCollectionConfig($%)
{   my ($self, $data, %args) = @_;

    my $format = (!exists $args{beautify} || $args{beautify}) ? 1 : 0;
    my $string;

    # create XML via XML::Compile
    my $writer = $self->{wr_coll_conf} ||=
      $self->compile
      ( WRITER => $coll_type
      , include_namespaces => 1, sloppy_integers => 1
      );

    my $doc    = XML::LibXML::Document->new('1.0', 'UTF-8');
    my $xml    = $writer->($doc, $data);
    $doc->setDocumentElement($xml);
    $doc->toString($format);
}

# perl -MXML::eXistDB -e 'print XML::eXistDB->new->_coll_conf_template'
sub _coll_conf_template { shift->template(PERL => $coll_type) }

=method decodeXML STRING
Received is a STRING produced by the server. Decode it, into the most
useful Perl data structure.
=cut

sub decodeXML($)
{   my $self  = shift;
    my $xml   = $self->dataToXML(shift);
    my $type  = type_of_node $xml;
    my $known = $self->namespaces->find(element => $type);
    $known ? $self->reader($type)->($xml) : XMLin $xml;
}

1;

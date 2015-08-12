use warnings;
use strict;

package XML::eXistDB;

use Log::Report 'xml-existdb', syntax => 'SHORT';

use XML::eXistDB::Util;
use XML::Compile::Util  qw/pack_type type_of_node/;
use XML::Compile::Cache ();
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

=c_method new %options

=option  schemas M<XML::Compile::Cache> object
=default schemas <created internally>
Overrule the location to load the schemas.

=cut

sub new(@) { my $class = shift; (bless {}, $class)->init({@_}) }

sub init($)
{   my ($self, $args) = @_;

    my $schemas = $self->{schemas} ||= XML::Compile::Cache->new;

    $schemas->allowUndeclared(1);
    $schemas->anyElement('SLOPPY');   # query results are sloppy
    $schemas->addCompileOptions('RW', sloppy_integers => 1, sloppy_floats => 1);
    $schemas->addPrefixes(exist => NS_EXISTDB);

    (my $xsddir = __FILE__) =~ s,\.pm,/xsd-exist,;
    my @xsds    = glob "$xsddir/*.xsd";
    $schemas->importDefinitions(\@xsds);

    $self;
}

#-----------------
=section Attributes
=method schemas
=cut

sub schemas() {shift->{schemas}}

#-----------------
=section Collection configuration (.xconf)

=method createCollectionConfig $data, %options
The $data structure should provide the needs for an collection configuration
file, in the shape C<XML::Compile> expects based on the schema. See the
C<template/collection.xconf>, which is part of the distribution.

=option  beautify BOOLEAN
=default beautify <true>
=cut

sub createCollectionConfig($%)
{   my ($self, $data, %args) = @_;
    my $format = (!exists $args{beautify} || $args{beautify}) ? 1 : 0;

    # create XML via XML::Compile
    my $doc    = XML::LibXML::Document->new('1.0', 'UTF-8');
    my $xml    = $self->schemas->writer($coll_type)->($doc, $data);
    $doc->setDocumentElement($xml);
    $doc->toString($format);
}

# perl -MXML::eXistDB -e 'print XML::eXistDB->new->_coll_conf_template'
sub _coll_conf_template { shift->schemas->template(PERL => $coll_type) }

=method decodeXML STRING
Received is a STRING produced by the server. Decode it, into the most
useful Perl data structure.
=cut

sub decodeXML($)
{   my $self    = shift;
    my $schemas = $self->schemas;
    my $xml     = $schemas->dataToXML(shift);

    my $type    = type_of_node $xml;
    my $known   = $schemas->namespaces->find(element => $type);
warn "READER $type=", $schemas->reader($type);
    $known ? $schemas->reader($type)->($xml) : XMLin $xml;
}

1;

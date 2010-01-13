use warnings;
use strict;

package XML::eXistDB::Util;
use base 'Exporter';

=chapter NAME
XML::eXistDB::Util - Constants and other general functions

=chapter SYNOPSIS
  use XML::eXistDB::Util;

=chapter DESCRIPTION

=chapter FUNCTIONS

=section namespaces
C<NS_COLLECTION_XCONF>, C<NS_EXISTDB>

=cut

our @EXPORT = qw/
    NS_COLLECTION_XCONF 
    NS_EXISTDB
    /;

use constant
  { NS_COLLECTION_XCONF => 'http://exist-db.org/collection-config/1.0'
  , NS_EXISTDB          => 'http://exist.sourceforge.net/NS/exist'
  };

1;

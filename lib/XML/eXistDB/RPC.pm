# This code is part of distribution XML-ExistsDB.  Meta-POD processed with
# OODoc into POD and HTML manual-pages.  See README.md
# Copyright Mark Overmeer.  Licensed under the same terms as Perl itself.

package XML::eXistDB::RPC;
use base 'XML::eXistDB';

use warnings;
use strict;

use Log::Report 'xml-existdb', syntax => 'LONG';

use XML::Compile::RPC::Util;
use XML::Compile::RPC::Client ();

use XML::eXistDB::Util;
use XML::eXistDB;

use Digest::MD5  qw/md5_base64 md5_hex/;
use Encode       qw/encode/;
use MIME::Base64 qw/encode_base64/;

use Data::Dumper;
$Data::Dumper::Indent = 1;

my $dateTime = 'dateTime.iso8601';  # too high chance on typos

=chapter NAME
XML::eXistDB::RPC - access eXist databases via RPC

=chapter SYNOPSIS
  my $db = XML::eXistDB::RPC->new(destination => $uri);
  my ($rc1, $h, $trace) = $db->describeUser('guest');
  $rc1==0 or die "Error: $h\n";

  my ($rc2, $set, $trace) = $db->executeQuery($query);
  my ($rc3, $answers, $trace) = $db->retrieveResults($set);

=chapter DESCRIPTION

This module is a full implementation of the fXML-RPC interface to the
eXist Database. This is not just an one-on-one implementation: some
methods are smarter and many methods are renamed to correct historical
mistakes. Hopefully, the result is more readible.

B<warning:> some methods are tested lightly, but a lot is B<not tested>
in real-life. I have a long list of bugs for eXist 1.4, and hope that
they will get fixed in a next release. Please do not be disappointed:
contribute tests and fixes!

B<warning:> be careful when upgrading to release until C<0.90>, because
they may change method behavior and naming, See ChangeLog!

=section Perl interface

The methods in this module provide access to all facilities the XML-RPC
protocol interface offers. However, some of these calls are on a lower
level than practical in a programmers interface. A few larger wrapper
methods were created, most importantly M<uploadDocument()> and
M<downloadDocument()>.

Some defaults can be set at initiation (M<new()>), such that repetition
can be avoided.

=section Definitions

The whole database (I<Repository>) contains sub-databases (I<Collections>),
which can have sub-collections themselves. Any collection contains
I<Documents> (indexable XML) and I<Binaries> (raw data). When both documents
and binaries are accepted, we speak about a I<Resource>.

=section Naming convensions
The XML-RPC method names are a mess: an typical example of many years
of growth. To repair that, consistent naming convensions are introduced.

Any method C<describeXXX()> collects a HASH with details about C<XXX>.
And any C<listXXX()> collects a list of C<XXX> names.  The typical Java
C<get> prefixes on some methods were removed in favor of better named
alternatives: sometimes C<list>, sometimes C<describe>, often something
completely different. Class attribute getters and setters naming should
not be used in interfaces (and are very not-Perl).

Most methods already had the form "<action><class>" (like "removeCollection"),
but on some random spots, the "class" was not present in the name.  This
has been repaired, which lowers the need to read the explanation of the
methods to understand what they are doing.

=section Return codes

RPC is a network protocol. Just like operating system calls: you shall
always check the return status of each call! Of course, this module could
simply ignore the existence of fault conditions, to provide a much simpler
programmers interface. But keep in mind: handling error conditions is
very important on the long run. A burdon for the first small programs,
but a desperate need for maintainability.

All methods return a LIST, where the first scalar is a return code (RC).
When that code is C<0>, all went well.  Otherwise, the code represent the
transport error or the exception (refusal) as reported by the server
logic.  In either case, the second scalar in the returned list contains
the error message.  For instance,

  my $user = guest;
  my ($rc, $details) = $db->describeUser($user);
  $rc==0
      or die "cannot get user info for `$user': $details ($rc)\n";

=chapter METHODS

=section Constructors

=c_method new %options

You must either specify your own L<XML::Compile::RPC::Client> object
with the C<rpc> option, or a C<destination> which will be used to create
such object.

=option  destination URI
=default destination <undef>
Where the RPC server is (the ExistDB access point).  For instance
C<http://localhost:8080/exist/xmlrpc>

=option  rpc OBJECT
=default rpc <undef>
An M<XML::Compile::RPC> object, which is used to communicate with
the server.  When not provided, one is created internally.

=option  repository STRING
=default repository '/db'
The repository; the top-level collection.

=option  compress_upload KILOBYTES
=default compress_upload 128
Compress the upload of resources when their size is over this number of
KILOBYTES in size. This will cost performance mainly on the client.

=option  chunk_size KILOBYTES
=default chunk_size 32
Send or download data in chunks (fragments) of this size when the size
exceeds this quantity.  If C<0>, then chunking is disabled.

=option  user USERNAME
=default user 'guest'
Used as default when a username is required. For now, that is only used
by M<lockResource()>.

=option  password STRING
=default password 'guest'

=option  prettyprint_upload BOOLEAN
=default prettyprint_upload <false>

=default schemas <created>
Schemas are by default shared with the xml-rpc client obect.

=option  format ARRAY|HASH
=default format []
The default for "options" which can be passed with many methods.
=cut

sub init($)
{   my ($self, $args) = @_;

    my $rpc = $args->{rpc};
    unless($rpc)
    {   my $dest = $args->{destination}
            or report ERROR =>
                    __x"{pkg} object required option `rpc' or `destination'"
                 , pkg => ref $self;
        $rpc = XML::Compile::RPC::Client->new(destination => $dest);
    }
    $args->{schemas} ||= $rpc->schemas;

    $self->SUPER::init($args);

    $self->{rpc}      = $rpc;
    $self->{repository}
      = exists $args->{repository} ? $args->{repository} : '/db';
    $self->{compr_up} = $args->{compress_upload} // 128;
    $self->{chunks}   = $args->{chunk_size}      // 32;

    $self->login($args->{user} // 'guest', $args->{password} // 'guest');
    $self->{pp_up}   = $args->{prettyprint_upload} ? 1 : 0;

    my $f = $args->{format} || [];
    $self->{format}  = [ ref $f eq 'HASH' ? %$f : @$f ];
    $self;
}

#-----------------
=section Attributes

=method rcpClient
Returns the xml-rpc client object which is used to communicate to
thse server.  See M<new(rpc)>.
=cut

sub rpcClient() {shift->{rpc}}

#-----------------
=section Helpers

=subsection Format (serialization parameters)

A number of methods support formatting options, to control the output.
With the method call, these parameters can be passed as list with pairs.
See F<http://exist-db.org/exist/apps/doc/xquery.xml>

 expand-xincludes=yes|no
 process-xsl-pi=yes|no
 highlight-matches=elements|attributes|both|none
 stylesheet=<path>
 method=xml|xhtml|json|text
 encoding=<string>
 jsonp=myFunctionName
 media-type=<string>
 doctype-public=<string>
 doctype-system=<string>
 indent=yes|no
 omit-xml-declaration=yes|no

 stylesheet-params=<HASH>
    provide stylesheet parameters.  The use of the "stylesheet-params"
    is simplified compared to the official XML-RPC description, with a
    nested HASH.

=cut

# private method; "options" is an overloaded term, abused by eXist.
sub _format(@)
{   my $self = shift;
    my %args = (@{$self->{format}}, @_);

    if(my $sp = delete $args{'stylesheet-params'})
    {   while(my($k,$v) = each %$sp)
        {   $args{"stylesheet-param.$k"} = $v;
        }
    }
    struct_from_hash string => \%args;
}

sub _date_options($$)
{   my ($created, $modified) = @_;

     !($created || $modified) ? ()
    : ($created && $modified) ? ($dateTime => $created, $dateTime => $modified)
    : report ERROR => "either both or neither creation and modification date";
}

# in Perl, any value is either true or false, in rpc only 0 and 1
sub _bool($) { $_[0] ? 0 : 1 }

=subsection Sending XML

Some method accept a DOCUMENT which can be a M<XML::LibXML::Document>
node, a string containing XML, a SCALAR (ref-string) with the same, or
a filename.
=cut

sub _document($)
{   my $self = shift;

    return $_[0]->toString($self->{pp_up})
        if UNIVERSAL::isa($_[0], 'XML::LibXML::Document');

    return encode 'utf-8', ${$_[0]}
        if ref $_[0] eq 'SCALAR';

    return encode 'utf-8', $_[0]
        if $_[0] =~ m/^\s*\</;

    if($_[0] !~ m/[\r\n]/ && -f $_[0])
    {   local *DOC;
        open DOC, '<:raw', $_[0]
            or report FAULT => "cannot read document from file $_[0]";
        local $/ = undef;
        my $xml = <DOC>;
        close DOC
            or report FAULT => "read error for document from file $_[0]";
        return $xml;
   }

   report ERROR => "do not understand document via $_[0]";
}

#-----------------
=section Repository

=method hasCollection $collection
Does the $collection identified by name exist in the repository?
=example
  my ($rc, $exists) = $db->hasCollection($name);
  $rc and die "$exists (RC=$rc)";
  if($exists) ...
=cut

#T
sub hasCollection($) { $_[0]->rpcClient->hasCollection(string => $_[1]) }

=method hasDocument $docname
Returns whether a document with NAME exists in the repository.
=example
  my ($rc, $exists) = $db->hasDocument($name);
  if($rc==0 && $exists) ....
=cut

sub hasDocument($) { $_[0]->rpcClient->hasDocument(string => $_[1]) }

=method isXACMLEnabled
Returns whether the eXtensible Access Control Markup Language (XACML)
by OASIS is enabled on the database.
=example
  my ($rc, $enabled) = $db->isACMLEnabled;
  if(!$rc && $enable) { ... }
=cut

#T
sub isXACMLEnabled() { shift->rpcClient->isXACMLEnabled }

=method backup $user, $password, $tocoll, $fromcoll
Returns success. Create a backup of the $fromcoll into the $tocoll, using
$user and $password to write it.  There is also an Xquery function to
produce backups.
=example
  my ($rc, $ok, $trace) = $db->backup('sys', 'xxx', '/db/orders', '/db/backup');
  $rc==0 or die "$rc $ok";
=cut

sub backup($$$$)
{   $_[0]->rpcClient->backup(string => $_[1], string => $_[2]
      , string => $_[3], string => $_[4]);
}

=method shutdown [$delay]
Shutdown the database.  The $delay is in milliseconds.
=example
  my ($rc, $success, $trace) = $db->shutdown(3000);  # 3 secs
  $rc==0 or die "$rc $success";
=cut

sub shutdown(;$)
{   my $self = shift;
    $self->rpcClient->shutdown(@_ ? (int => shift) : ());
}

=method sync
Force the synchronization of all db page cache buffers.
=example
  my ($rc, $success, $trace) = $db->sync;
=cut

sub sync() { shift->rpcClient->sync }

#-----------------
=section Collections

=method createCollection $collection, [$date]
Is a success if the collection already exists or can be created.
=example createCollection
  my $subcoll = "$supercoll/$myname";
  my ($rc, $success, $trace) = $db->createCollection($subcoll);
  $rc==0 or die "$rc $success";
=cut

#T
sub createCollection($;$)
{   my ($self, $coll, $date) = @_;
    my @date = $date ? ($dateTime => $date) : ();
    $self->rpcClient->createCollection(string => $coll, @date);
}

=method configureCollection $collection, $configuration, %options
The $configuration is a whole C<.xconfig>, describing the collection.
This can be a M<XML::LibXML::Document> node, a stringified XML
document, or a HASH.

When the $configuration is a HASH, the data will get formatted
by M<XML::eXistDB::createCollectionConfig()>.

The configuration will be placed in C</db/system/config/$collection>,
inside the database.

=option  beautify BOOLEAN
=default beautify <new(prettyprint_upload)>
Produce a readible configuration file.

=example
  my %index1   = (path => ..., qname => .., type => ...);
  my @indexes  = (\%index1, \%index2, \%index3);
  my %fulltext = (default => 'none', attributes => 0, alphanum => 0);
  my %trigger1 = (parameter => [ {name => 'p1', value => '42'} ];
  my @triggers = (\%trigger1, \%trigger2);

  my %config   =
    ( index      => {fulltext => \%fulltext, create => \@indexes}
    , triggers   => {trigger  => \@triggers};
    , validation => {mode     => 'yes'}
    );

  my ($rc, $ok, $trace) = $db->configureCollection($name, \%config);
=cut

#T
sub configureCollection($$%)
{   my ($self, $coll, $conf, %args) = @_;
    my $format = (exists $args{beautify} ? $args{beautify} : $self->{pp_up})
      ? 1 : 0;
    my $config;

    if(UNIVERSAL::isa($conf, 'XML::LibXML::Document'))
    {   # ready document, hopefully correct
        $config = $conf->toString($format);
    }
    elsif(!ref $conf && $conf =~ m/^\s*\</)
    {   # preformatted xml
        $config = $conf;
    }
    else
    {   $config = $self->createCollectionConfig($conf, %args);
    }

    $self->rpcClient->configureCollection(string => $coll, string => $config);
}

=method copyCollection $from, $to | <$tocoll, $subcoll>
Copy the $from collection to a new $to. With three arguments, $subcoll
is a collection within $tocoll.
=examples
  my ($rc, $ok, $trace) = $db->copyCollection('/db/from', '/db/some/to');
  my ($rc, $ok, $trace) = $db->copyCollection('/db/from', '/db/some', 'to');
=cut

sub copyCollection($$;$)
{   my ($self, $from, $sec) = (shift, shift, shift);
    my @param = (string => $from, string => $sec);
    push @param, string => shift if @_;
    $self->rpcClient->copyCollection(@param);
}

=method moveCollection $from, $to | <$tocoll, $subcoll>
Copy the $from collection to a new $to. With three arguments, $subcoll
is a collection within $tocoll.
=examples
  my ($rc, $ok, $trace) = $db->moveCollection('/db/from', '/db/some/to');
  my ($rc, $ok, $trace) = $db->moveCollection('/db/from', '/db/some', 'to');
=cut

# the two params version is missing from the interface description, so
# we use a little work-around
sub moveCollection($$;$)
{   my ($self, $from, $tocoll, $subcoll) = @_;
    defined $subcoll
        or ($tocoll, $subcoll) = $tocoll =~ m! ^ (.*) / ([^/]+) $ !x;

    $self->rpcClient->moveCollection(string => $from, string => $tocoll
      , string => $subcoll);
}

=method describeCollection [$collection], %options
Returns the RC and a HASH with details.  The details are the same as
returned with M<getCollectionDesc()>, excluding details about
documents.

=option  documents BOOLEAN
=default documents <false>

=example
  my ($rc, $descr, $trace) = $db->describeCollection($coll, documents => 1);
  $rc and die $rc;
  print Dumper $descr;  # Data::Dumper::Dumper
=cut

#T
sub describeCollection(;$%)
{   my $self = shift;
    my $coll = @_ % 2 ? shift : $self->{repository};
    my %args = @_;
    my ($rc, $data, $trace) = $args{documents}
      ? $self->rpcClient->getCollectionDesc(string => $coll)
      : $self->rpcClient->describeCollection(string => $coll);
    $rc==0 or return ($rc, $data, $trace);

    my $h = struct_to_hash $data;
    $h->{collections} = [ rpcarray_values $h->{collections} ];
    if(my $docs = $h->{documents})
    {   my %docs;
        foreach (rpcarray_values $docs)
        {   my $h = struct_to_hash $_;
            $docs{$h->{name}} = $h;
        }
        $h->{documents} =\%docs;
    }
    (0, $h, $trace);
}

=method subCollections [$collection]
[non-API] Returns a list of sub-collections for this collection, based
on the results of M<describeCollection()>. The returned names are made
absolute.
=example
  my ($rc, $subs, $trace) = $db->subCollections($coll);
  $rc and die "$rc $subs";
  print "@$subs\n";
=cut

#T
sub subCollections(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    my ($rc, $data, $trace) = $_[0]->describeCollection($coll, documents => 0);
    $rc==0 or return ($rc, $data, $trace);

    my @coll = map "$data->{name}/$_", @{$data->{collections} || []};
    (0, \@coll, $trace);
}

=method collectionCreationDate [$collection]
[non-API] Returns the date of the creation of the $collection, by default
from the root.
=example
  my ($rc, $date, $trace) = $db->collectionCreationDate($coll);
  $rc and die "$rc $date";
  print $date;  # f.i. "2009-10-21T12:13:13Z"
=cut

#T
sub collectionCreationDate(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    $self->rpcClient->getCreationDate(string => $coll);
}

=method listResources [$collection]
[non-API] Returns ... with all documents in the $collection. Without
$collection, it will list all documents in the whole repository.
=example
  my ($rc, $elems, $trace) = $db->listResources;
  $rc==0 or die "error: $elems ($rc)";
=cut

#T
sub listResources(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    my ($rc, $details, $trace)
       = $self->rpcClient->getDocumentListing($coll ? (string => $coll) : ());
    $rc==0 or return ($rc, $details, $trace);

    ($rc, [rpcarray_values $details], $trace);
}

=method reindexCollection $collection
Reindex all documents in a certain collection.
=example
   my ($rc, $success, $trace) = $db->reindexCollection($name);
   die "error: $success ($rc)" if $rc;
   die "failed" unless $success;
=cut

#T
sub reindexCollection($)
{   my ($self, $coll) = @_;
    $self->rpcClient->reindexCollection(string => $coll);
}

=method removeCollection $collection
Remove an entire collection from the database.
=example
   my ($rc, $success, $trace) = $db->removeCollection($name);
   die "error: $rc $success" if $rc;
   die "failed" unless $success;
=cut

#T
sub removeCollection($)
{   my ($self, $coll) = @_;
    $self->rpcClient->removeCollection(string => $coll);
}

#-----------------
=section Permissions

=method login $username, [$password]
[non-API] Change the $username (as known by ExistDB). When you specify
a non-existing $username or a wrong $password, you will not get more data
from this connection.  The next request will tell.
=cut

#T
sub login($;$)
{   my ($self, $user, $password) = @_;
    $self->{user}     = $user;
    $self->{password} = defined $password ? $password : '';
    $self->rpcClient->headers->header(Authorization => 'Basic '
      . encode_base64("$user:$password", ''));
    (0);
}

=method listGroups
[non-API] list all defined groups.
Returns a vector.
=example
  my ($rc, $groups, $trace) = $db->listGroups;
  $rc==0 or die "$groups ($rc)";
=cut

#T
sub listGroups()
{   my ($rc, $details, $trace) = shift->rpcClient->getGroups;
    $rc==0 or return ($rc, $details, $trace);
    (0, [rpcarray_values $details], $trace);
}

=method describeResourcePermissions $resource
[non-API] returns HASH with permission details about a $resource>
=cut

#T
sub describeResourcePermissions($)
{   my ($rc, $details, $trace) = $_[0]->rpcClient->getPermissions(string => $_[1]);
    $rc==0 or return ($rc, $details, $trace);
    ($rc, struct_to_hash $details, $trace);
}

=method listDocumentPermissions [$collection]
List the permissions for all resources in the $collection
=cut

#T
sub listDocumentPermissions($)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    my ($rc, $details, $trace)
      = $self->rpcClient->listDocumentPermissions(string => $coll);

    $rc==0 or return ($rc, $details, $trace);
    my $h = struct_to_hash $details;
    my %h;
    while( my ($k,$v) = each %$h)
    {   $h{$k} = [ rpcarray_values $v ];
    }
    (0, \%h, $trace);
}

=method describeAccount $username
[non-API] returns a HASH with user information.
=example
  my ($rc, $info) = $db->describeAccount($username);
  $rc==0 or die "error: $info ($rc)";
  my @groups = @{$info->{groups}};
=cut

#T
sub describeAccount($)
{   my ($self, $user) = @_;

    my $call = $self->serverVersion lt "3.0" ? 'getUser' : 'getAccount';
    my ($rc, $details, $trace) = $self->rpcClient->$call(string => $user);
    $rc==0 or return ($rc, $details, $trace);

    my $h = struct_to_hash $details;
    $h->{groups}   = [ rpcarray_values $h->{groups} ];
    $h->{metadata} = struct_to_hash $h->{metadata};
    (0, $h, $trace);
}

=method describeUser $username
DEPRECATED: use M<describeAccount()>.
=cut

*describeUser = \&describeAccount;

=method listAccounts
[non-API] Returns a LIST with all defined usernames.
=example
  my ($rc, @users) = $db->listAccounts;
  $rc==0 or die "error $users[0] ($rc)";
=cut

#T
sub listAccounts()
{   my $self = shift;
    my $call = $self->serverVersion lt "3.0" ? 'getUsers' : 'getAccounts';

    my ($rc, $details, $trace) = $self->rpcClient->$call;
    $rc==0 or return ($rc, $details, $trace);
    my %h;
    foreach my $user (rpcarray_values $details)
    {   my $u = struct_to_hash $user;
        $u->{groups}   = [ rpcarray_values $u->{groups} ];
        $u->{metadata} = struct_to_hash $u->{metadata};
        $h{$u->{name}} = $u;
    }
    (0, \%h, $trace);
}

=method listUsers
DEPRECATED: use M<listAccounts()>.
=cut

*listUsers = \&listAccounts;


=method removeAccount $username
Returns true on success.

=method removeUser $username
DEPRECATED: Renamed to M<removeAccount()> in existDB v3.0.

=cut

#T
sub removeAccount($)
{   my ($self, $username) = @_;
    my $call = $self->serverVersion lt "3.0" ? 'removeUser' : 'removeAccount';
    $_[0]->rpcClient->$call(string => $username);
}
*removeUser = \&removeAccount;

=method setPermissions $target, $permissions, [$user, $group]
The $target which is addressed is either a resource or a collection.

The $permissions are specified either as an integer value or using a
modification string. The bit encoding of the integer value corresponds
to Unix conventions (with 'x' is replaced by 'update'). The modification
string has as syntax:
  [user|group|other]=[+|-][read|write|update][, ...]

=cut

sub setPermissions($$;$$)
{   my ($self, $target, $perms, $user, $group) = @_;

    my @chown = ($user && $group) ? (string => $user, string => $group) : ();
    $self->rpcClient->setPermissions(string => $target, @chown
       , ($perms =~ m/\D/ ? 'string' : 'int') => $perms);
}

=method addAccount $user, $password, $groups, [$home]
Modifies or creates a repository user.
The $password is plain-text password. $groups are specified as single
scalar or and ARRAY. The first group is the user's primary group.

=method setUser $user, $password, $groups, [$home]
DEPRECATED: Renamed to M<addAccount()> in existDB v3.0.
=cut

#T
sub addAccount($$$;$)
{   my ($self, $user, $password, $groups, $home) = @_;
    my @groups = ref $groups eq 'ARRAY' ? @$groups : $groups;

    my $call = $self->serverVersion lt '3.0' ? 'setUser' : 'addAccount';

    $self->rpcClient->$call(string => $user
      , string => md5_base64($password)
      , string => md5_hex("$user:exist:$password")
      , rpcarray_from(string => @groups)
      , ($home ? (string => $home) : ())
      );
}
*setUser = \&addAccount;


=method describeCollectionPermissions [$collection]
Returns the RC and a HASH which shows the permissions on the $collection.
The output of the API is regorously rewritten to simplify implementation.

The HASH contains absolute collection names as keys, and then as values
a HASH with C<user>, C<group> and C<mode>.
=cut

#T
sub describeCollectionPermissions(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    my ($rc, $data, $trace)
      = $self->rpcClient->listCollectionPermissions(string => $coll);
    $rc==0 or return ($rc, $data, $trace);

    my $h = struct_to_hash $data;
    my %p;
    foreach my $relname (keys %$h)
    {  my %perms;
       @perms{ qw/user group mode/ } = rpcarray_values $h->{$relname};
       $p{"$coll/$relname"} = \%perms;
    }
    ($rc, \%p, $trace);
}

#-----------------
=section Resources

=method copyResource $from, $tocoll, $toname
=example
  my ($rc, $success, $trace) = $db->copyResource(...);
=cut

### need two-arg version?
sub copyResource($$$)
{   my $self = shift;
    $self->rpcClient->copyResource(string=> $_[0], string=> $_[1], string=> $_[2]);
}

=method uniqueResourceName [$collection]
Produces a random (and hopefully unique) resource-id (string) within
the $collection.  The returned id looks something like C<fe7c6ea4.xml>.
=example
  my ($rc, $id, $trace) = $db->uniqueResourceName($coll);
=cut

#T
sub uniqueResourceName(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    $self->rpcClient->createResourceId(string => $coll);
}

=method describeResource $resource
Returns details about a $resource (which is a document or a binary).
=example
  my ($rc, $details, $trace) = $db->describeResource($resource);
=cut

sub describeResource($)
{   my ($self, $resource) = @_;

    my ($rc, $details, $trace)
      = $self->rpcClient->describeResource(string => $resource);
    $rc==0 or return ($rc, $details, $trace);

    ($rc, struct_to_hash $details, $trace);
}

=method countResources [$collection]
[non-API] Returns the number of resources in the $collection.
=example
  my ($rc, $count, $trace) = $db->countResources($collection);
=cut

#T
sub countResources(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    $self->rpcClient->getResourceCount(string => $coll);
}

=method moveResource $from, $tocoll, $toname
=example
  my ($rc, $success) = $db->moveResource(...);
=cut

### two-params version needed?
sub moveResource($$$)
{   my $self = shift;
    $self->rpcClient->moveResource(string=> $_[0], string=> $_[1], string=> $_[2]);
}

=method getDocType $document
Returns details about the $document: the docname, public-id and system-id.
=example
  my ($rc, $d, $trace) = $db->getDocType($doc);
  print "$d->{docname} $d->{public_id} $d->{system_id}\n";
=cut

#T
sub getDocType($)
{   my ($rc, $details, $trace) = $_[0]->rpcClient->getDocType(string => $_[1]);
    $rc==0 or return ($rc, $details, $trace);

    my @d = rpcarray_values $details;
    ($rc, +{docname => $d[0], public_id => $d[1], system_id => $d[2]}, $trace);
}

=method setDocType $document, $typename, $public_id, $system_id
Add DOCTYPE information to a $document.

=example
  $rpc->setDocType($doc, "HTML"
     , "-//W3C//DTD HTML 4.01 Transitional//EN"
     , "http://www.w3.org/TR/html4/loose.dtd");

Will add to the document

  <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">
=cut

#T
sub setDocType($$$$)
{   my ($self, $doc, $name, $pub, $sys) = @_;
    $self->rpcClient->setDocType(string => $doc
      , string => $name, string => $pub, string => $sys);
}

=method whoLockedResource $resource
[non-API] Returns a username.

=example
   my ($rc, $user, $trace) = $db->whoLockedResource($resource);
=cut

sub whoLockedResource($) {$_[0]->rpcClient->hasUserLock(string => $_[1]) }

=method unlockResource $resource
Returns its success.
=example
   my ($rc, $ok, $trace) = $db->unlockedResource($resource);
=cut

sub unlockResource($) {$_[0]->rpcClient->unlockResource(string => $_[1]) }

=method lockResource $resource, [$username]
The default username is set by M<new(user)>.
=examples
   my ($rc, $ok, $trace) = $db->lockResource($resource);
   my ($rc, $ok, $trace) = $db->lockResource($resource, $user);
=cut

sub lockResource($;$)
{   my ($self, $resource, $user) = @_;
    $user ||= $self->{user}
        or report ERROR => "no default username set nor specified for lock";
    $self->rpcClient->lockResource(string => $resource, string => $user);
}

=method removeResource $docname
[non-API] remove a DOCument from the repository by NAME.  This method's name
is more consistent than the official API name C<remove()>.
=cut

sub removeResource($) { $_[0]->rpcClient->remove(string => $_[1]) }

#--------------------
=subsection Download documents

=method downloadDocument $resource, $format
Returns a document as byte array.
=cut

#T
sub downloadDocument($@)
{   my $self = shift;
    my ($rc, $chunk, $trace) = $self->getDocumentData(@_);
    my @trace = $trace;

    $rc==0 or return ($rc, $chunk, \@trace);

    my @data = \$chunk->{data};
    while($rc==0 && $chunk->{offset})
    {   ($rc, $chunk, $trace) = $chunk->{'supports-long-offset'}
        ? $self->getNextExtendedChunk($chunk->{handle}, $chunk->{offset})
        : $self->getNextChunk($chunk->{handle}, $chunk->{offset});

        $rc or push @data, \$chunk->{data};
        push @trace, $trace;
    }
    $rc==0 or return ($rc, $chunk, \@trace);

    (0, (join '', map $$_, @data), \@trace);
}

# does this also work for binary resources?

=method listResourceTimestamps $resource
[non-API] Returns the creation and modification dates.
=example
   my ($rc, $s, $trace) = $db->listResourceTimestamps($resource);
   $rc==0 or die "error: $s ($rc)";
   print "$s->{created} $s->{modified}\n";
=cut

sub listResourceTimestamps($)
{   my ($self, $resource) = @_;
    my ($rc, $stamps, $trace)
       = $self->rpcClient->getTimestamps(string => $resource);

    $rc==0 or return ($rc, $stamps, $trace);

    my @s = rpcarray_values $stamps;
    (0, +{created => $s[0], modified => $s[1]}, $trace);
}

#-----------------
=subsection Upload documents

=method uploadDocument $resource, $document, %options
[non-API] Hide all the different kinds of uploads via M<parse()> or
M<upload()> behind one interface.

It depends on the size of the document and the type of DATA provided,
whether M<upload()>, M<uploadCompressed()>, or M<parse()> is used to
transmit the data to the server.

=option  replace BOOLEAN
=default replace <false>

=option  mime_type STRING
=default mime_type 'text/xml'

=option  creation_date DATE
=default creation_date <undef>

=option  modify_date DATE
=default modify_date <undef>

=option  is_xml BOOLEAN  # treatAsXML
=default is_xml <false>

=option  compress KILOBYTES
=default compress <new(compress_upload)>

=option  beautify BOOLEAN
=default beautify <false>

=option  chunk_size KILOBYTES
=default chunk_size <new(chunk_size)>
=cut

#T
sub uploadDocument($$@)
{   my ($self, $resource, undef, %args) = @_;
    my $doc    = $self->_document($_[2]);

    my $chunks = exists $args{chunk_size} ? $args{chunk_size} : $self->{chunks};
    my $compr  = exists $args{compress} ? $args{compress} : $args{compr_upload};
    for ($chunks, $compr) { $_ *= 1024 if defined $_ } 

    my @dates   = _date_options $args{creation_date}, $args{modify_date};
    my $replace = $args{replace}   || 0;
    my $mime    = $args{mime_type} || 'text/xml';

    # Send file in chunks
    my $to_sent = length $doc;
    my $sent    = 0;

    my ($rc, $tmp, @trace);
    while($sent < $to_sent)
    {   ($rc, $tmp, my $t) = $self->upload($tmp, substr($doc, $sent, $chunks));
        push @trace, $t;
        $rc==0 or return ($rc, $tmp, \@trace);

        $sent += $chunks;
    }

    ($rc, my $d, my $t)
       = $self->parseLocal($tmp, $resource, $replace, $mime, @dates);
    push @trace, $t;
    ($rc, $d, \@trace);
}

=method downloadBinary $resource
[non-API] Get the bytes of a binary file from the server.
=example
  my ($rc, $bytes, $trace) = $db->downloadBinary($resource);
=cut

sub downloadBinary($) { $_[0]->rpcClient->getBinaryResource(string => $_[1]) }

=method uploadBinary $resource, $bytes, $mime, $replace, [$created, $modified]
[non-API] The $bytes can be passed as string or better as string reference.
=example
  my ($rc, $ok) = $db->storeBinaryResource($name, $bytes, 'text/html', 1);
=cut

sub uploadBinary($$$$;$$)
{   my ($self, $resource, $bytes, $mime, $replace, $created, $modified) = @_;
    
    $self->rpcClient->storeBinary
      ( base64 => (ref $bytes ? $$bytes : $bytes)
      , string => $resource, string => $mime, boolean => _bool $replace
      , _date_options($created, $modified)
      );
}

#-----------------
=section Queries

=subsection Compiled queries

=method compile $query, %format

=example
  my ($rc, $stats, $trace) = $db->compile($query);
=cut

#T
### compile doesn't return anything
sub compile($@)
{   my ($self, $query) = (shift, shift);
    my @format = $self->_format(@_);

    my ($rc, $d, $trace) = $self->rpcClient->compile(base64 => $query, @format);
    ($rc, ($rc==0 ? struct_to_hash($d) : $d), $trace);
}

=method describeCompile $query, %format
[non-API] Returns a string which contains the diagnostics of compiling
the query.
=cut

#T
# printDiagnostics should accept a base64
sub describeCompile($@)
{   my ($self, $query) = (shift, shift);
    my @format = $self->_format(@_);
    $self->rpcClient->printDiagnostics(string => $query, @format);
}

=method execute $queryhandle, $format
Returns a HASH.
=cut

sub execute($@)
{   my ($self, $handle) = (shift, shift);
    my @format = $self->_format(@_);
    my ($rc, $d, $trace) = $self->rpcClient->execute(string => $handle, @format);
    ($rc, ($rc==0 ? struct_to_hash $d : $d), $trace);
}

#-----------------
=subsection Query returns result as set

=method executeQuery $query, [$encoding], [$format]
Run the $query given in the specified $encoding.  Returned is
only an identifier to the result.

=example
   my ($rc1, $set,   $trace1) = $db->executeQuery($query);
   my ($rc2, $count, $trace2) = $db->numberOfResults($set);
   my ($rc3, $data,  $trace3) = $db->retrieveResults($set);
   $db->releaseResults($set);
=cut

sub executeQuery($@)
{   my ($self, $query) = @_;
    my @args = (base64 => $query);
    push @args, string => shift if @_ %2;
    push @args, $self->_format(@_);
    $self->rpcClient->executeQuery(@args);
}

=method numberOfResults $resultset
[non-API] Returns the number of answers in the RESULT set of a query.
Replaces C<getHits()>.
=cut

sub numberOfResults($) { $_[0]->rpcClient->getHits(int => $_[1]) }

=method describeResultSet $resultset
[non-API] Retrieve a summary of the result set identified by it's
result-set-id. This method returns a HASH with simple values
C<queryTime> (milli-seconds) and C<hits> (number of results).
Besides, it contains complex structures C<documents> and C<doctypes>.
=cut

#T
# what does "docid" mean?
sub describeResultSet($)
{   my ($self, $set) = @_;

    my ($rc, $details,$trace) = $self->rpcClient->querySummary(int => $set);
    $rc==0 or return ($rc, $details, $trace);
    my $results = struct_to_hash $details;

    if(my $docs = delete $results->{documents})
    {   my @docs;
        foreach my $result (rpcarray_values $docs)
        {   my ($name, $id, $hits) = rpcarray_values $result;
            push @docs, +{ name => $name, docid => $id, hits => $hits };
        }
        $results->{documents} = \@docs;
    }
    if(my $types = delete $results->{doctypes})
    {   my @types;
        foreach my $result (rpcarray_values $types)
        {   my ($class, $hits) = rpcarray_values $result;
            push @types, +{ class => $class, hits => $hits };
        }
        $results->{doctypes} = \@types;
    }
    ($rc, $results, $trace);
}

=method releaseResultSet $resultset, [$params]
[non-API] Give-up on the $resultset on the server.
=cut

#### what kind of params from %args?
#### releaseQueryResult(int $resultid, int $hash)   INT?
sub releaseResultSet($@)
{   my ($self, $results, %args) = @_;
    $self->rpcClient->releaseQueryResult(int => $results, int => 0);
}

=method retrieveResult $resultset, $pos, [$format]
[non-API] retrieve a single result from the $resultset.
Replaces M<retrieve()> and M<retrieveFirstChunk()>.
=cut

sub retrieveResult($$@)
{   my ($self, $set, $pos) = (shift, shift, shift);
    my @format = $self->_format(@_);

    my ($rc, $bytes, $trace)
       = $self->rpcClient->retrieve(int => $set, int => $pos, @format);
    $rc==0 or return ($rc, $bytes, $trace);

    (0, $self->decodeXML($bytes), $trace);
}

=method retrieveResults $resultset, [$format]
Replaces M<retrieveAll()> and M<retrieveAllFirstChunk()>.
=cut

# hitCount where describeResultSet() uses 'hits'
#T
sub retrieveResults($@)
{   my ($self, $set) = (shift, shift);
    my @format = $self->_format(@_);

    my ($rc, $bytes, $trace) = $self->rpcClient->retrieveAll(int => $set, @format);
    $rc==0 or return ($rc, $bytes, $trace);

    (0, $self->decodeXML($bytes), $trace);
}

#-----------------
=subsection Query returns result

=method query $query, $limit, [$first], [$format]
Returns a document of the collected results.

This method is deprecated according to the java description, in favor of
M<executeQuery()>, however often used for its simplicity.
=cut

#T
# Vector query() is given as alternative but does not exist.
sub query($$$@)
{   my ($self, $query, $limit) = (shift, shift, shift);
    my $first  = @_ % 2 ? shift : 1;
    my @format = $self->_format(@_);

    my ($rc, $bytes, $trace) = $self->rpcClient
      ->query(string => $query, int => $limit, int => $first, @format);
    $rc==0 or return ($rc, $bytes, $trace);

    (0, $self->decodeXML($bytes), $trace);
}

=method queryXPath $xpath, $docname, $node_id, %options
When DOCUMENT is defined, then the search is limited to that document,
optionally further restricted to the NODE with the indicated ID.

=example
  my ($rc, $h) = $db->queryXPath($xpath);
=cut

sub queryXPath($;$$@)
{   my ($self, $xpath, $doc, $node) = splice @_, 0, 4;
    my @args = (base64 => $xpath);
    push @args, string => $doc, string => $node // ''
        if defined $doc;
    push @args, $self->_format(@_);

    my ($rc, $data, $trace) = $self->rpcClient->queryP(@args);
    $rc==0 or return ($rc, $data, $trace);

    my $h = struct_to_hash $data;
    my @r;
    foreach my $v (rpcarray_values $h->{results})
    {   if(ref $v eq 'HASH')
        {   #XXX is this correct?
            my ($doc, $loc) = rpcarray_values $v;
            push @r, +{document => $doc, node_id => $loc};
        }
        push @r, $v;
    }
    $h->{results} = \@r;

    (0, $h, $trace);
}
 
#-----------------
=subsection Simple node queries

=method retrieveDocumentNode $document, $nodeid, [$format]
[non-API] Collect one node from a certain document. Doesn't matter
how large: this method will always work (by always using chunks).
=cut

sub retrieveDocumentNode($$@)
{   my $self = shift;
    my ($rc, $chunk, $trace) = $self->rpcClient->retrieveFirstChunk(@_);

    my @data = \$chunk->{data};
    while($rc==0 && $chunk->{offset})
    {   ($rc, $chunk) = $chunk->{'supports-long-offset'}
        ? $self->getNextExtendedChunk($chunk->{handle}, $chunk->{offset})
        : $self->getNextChunk($chunk->{handle}, $chunk->{offset});
        $rc or push @data, \$chunk->{data};
    }
    $rc==0 or return ($rc, $chunk, $trace);

    (0, $self->decodeXML(join '', map $$_, @data), $trace);
}

#-----------------
=subsection Modify document content

=method updateResource $resource, $xupdate, [$encoding]
=example
  my ($rc, $some_int, $trace) = $db->updateResource($resource, $xupdate);
=cut

### What does the returned int mean?
sub updateResource($$;$)
{   my ($self, $resource, $xupdate, $encoding) = @_;
    $self->rpcClient->xupdateResource(string => $resource, string => $xupdate
      , ($encoding ? (string => $encoding) : ()));
}

### What does the returned int mean?
### Does this update the collection configuration?
=method updateCollection $collection, $xupdate
[non-API]
=example
  my ($rc, $some_int, $trace) = $db->updateCollection($coll, $xupdate);
=cut

sub updateCollection($$)
{   $_[0]->rpcClient->xupdate(string => $_[1], string => $_[2]);
}

#-----------------
=section Indexing

=method scanIndexTerms $collection, $begin, $end, $recursive

or C<< $db->scanIndexTerms($xpath, $begin, $end) >>.

=examples
  my ($rc, $occ, $trace) = $db->scanIndexTerms($xpath, $begin, $end);
  my ($rc, $occ) = $db->scanIndexTerms($coll, $begin, $end, $recurse);
=cut

sub scanIndexTerms($$$;$)
{   my $self = shift;
     my ($rc, $details, $trace);
    if(@_==4)
    {   my ($coll, $begin, $end, $recurse) = @_;
        ($rc, $details, $trace) = $self->rpcClient->scanIndexTerms(string => $coll
          , string => $begin, string => $end, boolean => _bool $recurse);
    }
    else
    {   my ($xpath, $begin, $end) = @_;
        ($rc, $details, $trace) = $self->rpcClient->scanIndexTerms(string => $xpath
          , string => $begin, string => $end);
    }

    $rc==0 or return ($rc, $details, $trace);

    # XXX this has not been tested.  Probably we need to unpack each @occ
    #     via struct_to_hash
    my @occ = rpcarray_values $details;
    ($rc, \@occ, $trace);
}

=method indexedElements $collection, $recursive
=cut

sub indexedElements($$)
{   my ($self, $coll, $recurse) = @_;
    my ($rc, $details, $trace)
      = $self->rpcClient->getIndexedElements(string => $coll
         , boolean => _bool $recurse);
    $rc==0 or return ($rc, $details, $trace);

### cleanup Vector $details. Per element:
#  1. name of the element
#  2. optional namespace URI
#  3. optional namespace prefix
#  4. number of occurrences of this element as an integer value

    (0, [rpcarray_values $details], $trace);
}


#-----------------
=section Helpers

=method trace
Returns the trace information from the last command executed over RPC. Nearly
all methods in this class only perform one RPC call. You can find the timings,
http request, and http response in the returned HASH.

=examples

  my ($rc, $d, $trace) = $db->getDocType($doc);  # is equivalent to

  my ($rc, $d) = $db->getDocType($doc);
  my $trace    = $db->trace;

=cut

sub trace() { shift->rpcClient->trace }

#----------------
=section Please avoid
Some standard API methods have gotten more powerful alternatives.  Please
avoid using the methods described in this section (although they do work)

=subsection Please avoid: collections

=method getCollectionDesc [$collection]
Please use M<describeCollection()> with option C<< documents => 1 >>.
=cut

#T
sub getCollectionDesc(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    $self->describeCollection($coll, documents => 1);
}

#---------
=subsection Please avoid: download documents

=method getDocument $resource, $format|<$encoding, $pretty, $style>
Please use M<downloadDocument()>.  Either specify $format parameters
(a list of pairs), or three arguments.  In the latter case, the
$style must be present but may be C<undef>.  $style refers to a
stylesheet document.
=cut

sub getDocument($$;$$)
{   my ($self, $resource) = (shift, shift);
    my @args;
    if(@_==3)
    {   my ($enc, $prettyprint, $style) = @_;
        push @args, string => $enc, int => ($prettyprint ? 1 : 0);
        push @args, string => $style if defined $style;
    }
    else
    {   @args = @_;
    }
    $self->rpcClient->getDocument(string => $resource, @args);
}

=method getDocumentAsString $resource, $format|<$encoding, $pretty, $style>
Please use M<downloadDocument()>. See M<getDocument()>.
=cut

sub getDocumentAsString($$;$$)
{   my ($self, $resource) = (shift, shift);
    my @args;
    if(@_==3)
    {   my ($enc, $prettyprint, $style) = @_;
        push @args, string => $enc, int => ($prettyprint ? 1 : 0);
        push @args, string => $style if defined $style;
    }
    else
    {   @args = @_;
    }
    $self->rpcClient->getDocumentAsString(string => $resource, @args);
}

=method getDocumentData $resource, $format
Please use M<downloadDocument()>.
Retrieve the specified document, but limit the number of bytes
transmitted to avoid memory shortage on the server. The size of the
chunks is controled by the server.  Returned is a HASH.

When the returned HASH contains C<supports-long-offset>, then get the
next Chunk with M<getNextExtendedChunk()> otherwise use M<getNextChunk()>.

=example
   my ($rc, $chunk, $trace) = $db->getDocumentData($resource);
   my $doc = $chunk->{data};
   while($rc==0 && $chunk->{offset}!=0)
   {   ($rc, $chunk, $trace) = $chunk->{'supports-long-offset'}
       ? $db->getNextExtendedChunk($chunk->{handle}, $chunk->{offset})
       : $db->getNextChunk($chunk->{handle}, $chunk->{offset});
       $rc==0 and $doc .= $chunk->{data};
   }
   $rc==0 or die "error: $chunk ($rc)";
       
=cut

sub getDocumentData($@)
{   my ($self, $resource) = (shift, shift);
    my @format = $self->_format(@_);

    my ($rc, $d, $trace)
       = $self->rpcClient->getDocumentData(string => $resource, @format);

    ($rc, ($rc==0 ? struct_to_hash $d : $d), $trace);
}

=method getNextChunk $tmpname, $offset
Collect the next chunk, initiated with a M<getDocumentData()>. The file
is limited to 2GB.
=cut

sub getNextChunk($$)
{   my ($self, $handle, $offset) = @_;
    my ($rc, $d, $trace)
      = $self->rpcClient->getNextChunk(string => $handle, int => $offset);
    ($rc, ($rc==0 ? struct_to_hash $d : $d), $trace);
}

=method getNextExtendedChunk $tmpname, $offset
Collect the next chunk, initiated with a M<getDocumentData()>. This method
can only be used with servers which run an eXist which supports long files.
=cut

sub getNextExtendedChunk($$)
{   my ($self, $handle, $offset) = @_;
    my ($rc, $d, $trace)
      = $self->rpcClient->getNextChunk(string => $handle, string => $offset);
    ($rc, ($rc==0 ? struct_to_hash $d : $d), $trace);
}

#---------
=subsection Please avoid: uploading documents

=method parse $document, $resource, [$replace, [$created, $modified]]
Please use M<uploadDocument()>.
Store the $document of a document under the $resource name into the
repository. When $replace is true, it will overwrite an existing document
when it exists.

The DATA can be a string containing XML or M<XML::LibXML::Document>.
=cut

sub parse($$;$$$)
{   my ($self, $data, $resource, $replace, $created, $modified) = @_;
   
    $self->rpcClient->parse
      ( base64 => $self->_document($data)
      , string => $resource, int => ($replace ? 1 : 0)
      , _date_options($created, $modified)
      );
}

=method parseLocal $tempname, $resource, $replace, $mime, [$created, $modified]
Please use M<uploadDocument()>.
Put the content of document which was just oploaded to the server under some
$tempname (received from M<upload()>), as $resource in the database.

NB: B<Local> means "server local", which is remote for us as clients.
=cut

sub parseLocal($$$$;$$)
{   my ($self, $fn, $resource, $replace, $mime, $created, $modified) = @_;
   
    $self->rpcClient->parseLocal
      ( string => $fn, string => $resource, boolean => _bool $replace
      , string => $mime, _date_options($created, $modified)
      );
}

=method parseLocalExt $tempname, $resource, $replace, $mime, $isxml, [$created, $modified]
Please use M<uploadDocument()>.
Put the content of document which was just oploaded with M<upload()> to
the server under some $tempname (received from M<upload()>) as $resource
in the database. Like M<parseLocal()>, but with extra C<$isxml> boolean,
to indicate that the object is XML, where the server does not know that
from the mime-type.

NB: B<Local> means "server local", which is remote for us as clients.
=cut

sub parseLocalExt($$$$;$$)
{   my ($self, $fn, $res, $replace, $mime, $is_xml, $created, $modified) = @_;
   
    $self->rpcClient->parseLocal
      ( string => $fn, string => $res, boolean => _bool $replace
      , string => $mime, boolean => _bool $is_xml
      , _date_options($created, $modified)
      );
};

=method upload [$tempname], $chunk
Please use M<uploadDocument()>.
Upload a document in parts to the server. The first upload will give
you the TEMPoraryNAME for the object. You may leave that name out or
explicitly state C<undef> at that first call.  When all data is uploaded,
call M<parseLocal()> or M<parseLocalExt()>.

=example
   # start uploading
   my ($rc1, $tmp, $trace) = $db->upload(undef, substr($data, 0, 999));
   my ($rc1, $tmp)  = $db->upload(substr($data, 0, 999));  # same

   # send more chunks
   my ($rc2, undef) = $db->upload($tmp, substr($data, 1000));

   # insert the document in the database
   my ($rc3, $ok)   = $db->parseLocal($tmp, '/db/file.xml', 0, 'text/xml')
      if $rc1==0 && $rc2==0;
=cut

sub upload($;$)
{   my $self = shift;
    my $tmp  = @_ == 2 ? shift : undef;
    $self->rpcClient->upload(string => (defined $tmp ? $tmp : '')
       , base64 => $_[0], int => length($_[0]));
}

=method uploadCompressed [$tempname], $chunk
Please use M<uploadDocument()>.
Like M<upload()>, although the chunks are part of a compressed file.
=cut

sub uploadCompressed($;$)
{   my $self = shift;
    my $tmp  = @_ == 3 ? shift : undef;

### Not sure whether each chunk is compressed separately or the
### data is compressed as a whole.
    $self->rpcClient->uploadCompressed
       ( (defined $tmp ? (string => $tmp) : ())
       , base64 => $_[0], int => length($_[1]));
}

=method storeBinary $bytes, $resource, $mime, $replace, [$created, $modified]
Please use M<uploadBinary()>.
=cut

sub storeBinary($$$$;$$) { $_[0]->uploadBinary( @_[2, 1, 3, 4, 5, 6] ) }

#-------
=subsection Please avoid: simple node queries

=method retrieveFirstChunk <($doc, $nodeid) | ($resultset, $pos)>, [$format]
Please use M<retrieveDocumentNode()> or M<retrieveResult()>.
Two very different uses for this method: either retrieve the first part
of a single node from a document, or retrieve the first part of an
answer in a result set.  See M<getNextChunk()> for the next chunks.
=cut

sub retrieveFirstChunk($$@)
{   my $self = shift;
    my @args;
    if($_[0] =~ m/\D/)
    {   my ($docname, $id) = (shift, shift);
        @args = (string => $docname, string => $id);
    }
    else
    {   my ($resultset, $pos) = (shift, shift);
        @args = (int => $resultset, int => $pos);
    }
    my @format = $self->_format(@_);
    my ($rc, $d, $trace) = $self->rpcClient->retrieveFirstChunk(@args, @format);
    ($rc, ($rc==0 ? $d : struct_to_hash $d), $trace);
}

#------------------
=subsection Please avoid: collect query results

=method retrieve <($doc, $nodeid) | ($resultset, $pos)>, [$format]
Please use M<retrieveResult()> or M<retrieveDocumentNode()>.
=cut

sub retrieve($$@)
{   my $self = shift;
    my @args = $_[0] =~ m/\D/
             ? (string => shift, string => shift)
             : (int => shift, int => shift);
    push @args, $self->_format(@_);

    my ($rc, $bytes, $trace) = $self->rpcClient->retrieve(@args);
    ($rc, ($rc==0 ? $self->decodeXML($bytes) : $bytes), $trace);
}

=method retrieveAll $resultset, [$format]
Please use M<retrieveResults()>.
=cut

sub retrieveAll($$@)
{   my ($self, $set) = (shift, shift);
    my @format = $self->_format(@_);

    my ($rc, $bytes, $trace)
      = $self->rpcClient->retrieveAll(int => $set, @format);
    ($rc, ($rc==0 ? $self->decodeXML($bytes) : $bytes), $trace);
}

=method retrieveAllFirstChunk $resultset, [$format]
Please use M<retrieveResults()>.
=cut

sub retrieveAllFirstChunk($$@)
{   my ($self, $result) = (shift, shift);
    my @format = $self->_format(@_);

    my ($rc, $d, $trace)
      = $self->rpcClient->retrieveAllFirstChunk(int => $result, @format);

    ($rc, ($rc==0 ? struct_to_hash($d) : $d), $trace);
}

=method isValidDocument $document
Returns true when the $document (inside the database) is validated as
correct.
=cut

sub isValidDocument($)
{   my ($self, $doc) = (shift, shift);
    $self->rpcClient->isValid(string => $doc);
}

=method initiateBackup $directory
Trigger the backup task to write to the $directory. Returns true, always,
but that does not mean success: the initiation will succeed.
=cut

sub initiateBackup($)
{   my ($self, $s) = (shift, shift);
    $self->rpcClient->dataBackup($s);
}

=method getDocumentChunked $docname, %options
Please use M<downloadDocument()>
=example
   my ($rc, $handle, $total_length, $trace) = $db->getDocumentChuncked($doc);
   my $xml = $db->getDocumentNextChunk($handle, 0, $total_length-1);
=cut

sub getDocumentChunked($@)
{   my ($self, $doc) = (shift, shift);
    my ($rc, $data, $trace) = $self->rpcClient->getDocumentChunk(string=> $doc);
    $rc==0 or return ($rc, $data, $trace);

    my ($h, $l) = rpcarray_values $data;
    (0, $h, $l, $trace);
}

=method getDocumentNextChunk $handle, $start, $length
=cut

sub getDocumentNextChunk($$$)
{   my ($self, $handle, $start, $len) = @_;
    $self->rpcClient->getDocumentChunck(string => $handle
      , int => $start, int => $len);
}

=method retrieveAsString $document, $nodeid, %options
=cut

sub retrieveAsString($$@)
{   my ($self, $doc, $node) = (shift, shift, shift);
    $self->rpcClient->retrieveAsString(string => $doc, string => $node
      , $self->_format(@_));
}

#----------------
=section Renamed methods
Quite a number of API methods have been renamed to be more consistent
with other names.  Using the new names should improve readibility. The
original names are still available:

  -- xml-rpc name           -- replacement name
  createResourceId          => uniqueResourceName
  dataBackup                => initiateBackup
  getBinaryResource         => downloadBinary
  getCreationDate           => collectionCreationDate
  getDocumentListing        => listResources
  getGroups                 => listGroups
  getHits                   => numberOfResults
  getIndexedElements        => indexedElements
  getPermissions            => describeResourcePermissions
  getResourceCount          => countResources
  getTimestamps             => listResourceTimestamps
  getUser     [<3.0]        => describeAccount
  getAccount  [>3.0]        => describeAccount
  getUsers    [<3.0]        => listAccounts
  getAccounts [>3.0]        => listAccounts
  hasUserLock               => whoLockedResource
  isValid                   => isValidDocument
  listCollectionPermissions => describeCollectionPermissions
  printDiagnostics          => describeCompile
  queryP                    => queryXPath
  querySummary              => describeResultSet
  releaseQueryResult        => releaseResultSet
  remove                    => removeResource
  xupdate                   => xupdateCollection
  xupdateResource           => xupdateResource
=cut

*createResourceId = \&uniqueResourceName;
*dataBackup = \&initiateBackup;
*getBinaryResource = \&downloadBinary;
*getCreationDate = \&collectionCreationDate;
*getDocumentListing = \&listResources;
*getIndexedElements = \&indexedElements;
*getGroups = \&listGroups;
*getHits = \&numberOfResults;
*getPermissions = \&describeResourcePermissions;
*getResourceCount = \&countResources;
*getTimestamps = \&listResourceTimestamps;
*getUser    = \&describeAccount;
*getAccount = \&describeAccount;
*getUsers   = \&listUsers;
*hasUserLock = \&whoLockedResource;
*isValid = \&isValidDocument;
*listCollectionPermissions = \&describeCollectionPermissions;
*printDiagnostics = \&describeCompile;
*querySummary = \&describeResultSet;
*queryP = \&queryXPath;
*releaseQueryResult = \&releaseResultSet;
*remove = \&removeResource;
*xupdate = \&xupdateCollection;
*xupdateResource = \&xupdateResource;

1;

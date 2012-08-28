use warnings;
use strict;

package XML::eXistDB::RPC;

use Log::Report 'xml-existdb', syntax => 'LONG';

use XML::Compile::RPC::Util;
use XML::Compile::RPC::Client ();

use XML::eXistDB::Util;
use XML::eXistDB;

use Digest::MD5  qw/md5_base64 md5_hex/;
use Encode       qw/encode/;
use MIME::Base64 qw/encode_base64/;

# to be removed later
use Data::Dumper;
$Data::Dumper::Indent = 1;

my $dateTime = 'dateTime.iso8601';  # too high chance on typos

=chapter NAME
XML::eXistDB::RPC - access eXist databases via RPC

=chapter SYNOPSYS
  my $db = XML::eXistDB::RPC->new(destination => $uri);
  my ($rc1, $h) = $db->describeUser('guest');
  $rc1==0 or die "Error: $h\n";

  my ($rc2, $set) = $db->executeQuery($query);
  my ($rc3, @answers) = $db->retrieveResults($set);

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

=c_method new OPTIONS

You must either specify your own L<XML::Compile::RPC::Client> object
with the C<rpc> option, or a C<destination> which will be used to create
such object.

=option  destination URI
=default destination <undef>
Where the RPC server is (the ExistDB access point)

=option  rpc OBJECT
=default rpc <undef>

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

=option  schemas OBJECT
=default schemas <created>
When you need to do complex things with the eXist schema's, you
may prepare an M<XML::eXistDB> object beforehand. However, that
shouldn't be needed under normal cicumstances. By default, such
object is created for you.

=option  format ARRAY|HASH
=default format []
The default for "options" which can be passed with many methods.
=cut

sub new(@) { my $class = shift; (bless {}, $class)->init({@_}) }

sub init($)
{   my ($self, $args) = @_;

    unless($self->{rpc} = $args->{rpc})
    {   my $dest = $args->{destination}
            or report ERROR =>
                    __x"{pkg} object required option `rpc' or `destination'"
                 , pkg => ref $self;
        $self->{rpc} = XML::Compile::RPC::Client->new(destination => $dest);
    }

    $self->{repository}
      = exists $args->{repository} ? $args->{repository} : '/db';
    $self->{compr_up}
      = defined $args->{compress_upload} ? $args->{compress_upload} : 128;
    $self->{chunks}  = defined $args->{chunk_size} ? $args->{chunk_size} : 32;

    $self->login($args->{user} || 'guest', $args->{password} || 'guest');
    $self->{pp_up}   = $args->{prettyprint_upload} ? 1 : 0;
    $self->{schemas} = $args->{schemas};

    my $f = $args->{format} || [];
    $self->{format}  = [ ref $f eq 'HASH' ? %$f : @$f ];
    $self;
}

#-----------------
=section Helpers

=subsection Format

A number of methods support formatting options, to control the output.
With the method call, these parameters can be passed as list with pairs.

 indent:  returns indented pretty-print XML.         yes|no
 encoding: character encoding used for the output.   <string>
 omit-xml-declaration: XML declaration to the head.  yes|no
 expand-xincludes: expand XInclude elements.         yes|no
 process-xsl-pi: apply stylesheet to the output.     yes|no
 highlight-matches: show result from fulltext search.elements|attributes|both
 stylesheet: to apply. rel-path from database        <path>
 stylesheet-params: stylesheet params                <HASH>

The use of the "stylesheet-params" is simplified compared to the official
XML-RPC description, with a nested HASH.
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

=method hasCollection COLLECTION
Does the COLLECTION identified by name exist in the repository?
=example
  my ($rc, $exists) = $db->hasCollection($name);
  $rc and die "$exists (RC=$rc)";
  if($exists) ...
=cut

#T
sub hasCollection($) { $_[0]->{rpc}->hasCollection(string => $_[1]) }

=method hasDocument DOCNAME
Returns whether a document with NAME exists in the repository.
=example
  my ($rc, $exists) = $db->hasDocument($name);
  if($rc==0 && $exists) ....
=cut

sub hasDocument($) { $_[0]->{rpc}->hasDocument(string => $_[1]) }

=method isXACMLEnabled
Returns whether the eXtensible Access Control Markup Language (XACML)
by OASIS is enabled on the database.
=example
  my ($rc, $enabled) = $db->isACMLEnabled;
  if(!$rc && $enable) { ... }
=cut

#T
sub isXACMLEnabled() {shift->{rpc}->isXACMLEnabled}

=method backup USER, PASSWORD, TOCOLL, FROMCOLL
Returns success. Create a backup of the FROMCOLL into the TOCOLL, using
USERname and PASSWORD to write it.  There is also an Xquery function to
produce backups.
=example
  my ($rc, $ok) = $db->backup('sys', 'xxx', '/db/orders', '/db/backup');
  $rc==0 or die "$rc $ok";
=cut

sub backup($$$$)
{   $_[0]->{rpc}->backup(string => $_[1], string => $_[2]
      , string => $_[3], string => $_[4]);
}

=method shutdown [DELAY]
Shutdown the database.  The DELAY is in milliseconds.
=example
  my ($rc, $success) = $db->shutdown(3000);  # 3 secs
  $rc==0 or die "$rc $success";
=cut

sub shutdown(;$)
{   my $self = shift;
    $self->{rpc}->shutdown(@_ ? (int => shift) : ());
}

=method sync
Force the synchronization of all db page cache buffers.
=example
  my ($rc, $success) = $db->sync;
=cut

sub sync() { shift->{rpc}->sync }

#-----------------
=section Collections

=method createCollection COLLECTION, [DATE]
Is a success if the collection already exists or can be created.
=example createCollection
  my $subcoll = "$supercoll/$myname";
  my ($rc, $success) = $db->createCollection($subcoll);
  $rc==0 or die "$rc $success";
=cut

#T
sub createCollection($;$)
{   my ($self, $coll, $date) = @_;
    my @date = $date ? ($dateTime => $date) : ();
    $self->{rpc}->createCollection(string => $coll, @date);
}

=method	configureCollection COLLECTION, CONFIGURATION, OPTIONS
The CONFIGURATION is a whole C<.xconfig>, describing the collection.
This can be a M<XML::LibXML::Document> node, a stringified XML
document, or a HASH.

When the CONFIGURATION is a HASH, the data will get formatted
by M<XML::eXistDB::createCollectionConfig()>.

The configuration will be placed in C</db/system/config$COLLECTION>,
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

  my ($rc, $success) = $db->configureCollection($name, \%config);
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
    {   $config = $self->schemas->createCollectionConfig($conf, %args);
    }

    $self->{rpc}->configureCollection(string => $coll, string => $config);
}

=method copyCollection FROM, TO | (TOCOLL, SUBCOLL)
Copy the FROM collection to a new TO. With three arguments, SUBCOLL
is a collection within TOCOLL.
=examples
  my ($rc, $succ) = $db->copyCollection('/db/from', '/db/some/to');
  my ($rc, $succ) = $db->copyCollection('/db/from', '/db/some', 'to');
=cut

sub copyCollection($$;$)
{   my ($self, $from, $sec) = (shift, shift, shift);
    my @param = (string => $from, string => $sec);
    push @param, string => shift if @_;
    $self->{rpc}->copyCollection(@param);
}

=method moveCollection FROM, TO | (TOCOLL, SUBCOLL)
Copy the FROM collection to a new TO. With three arguments, SUBCOLL
is a collection within TOCOLL.
=examples
  my ($rc, $succ) = $db->moveCollection('/db/from', '/db/some/to');
  my ($rc, $succ) = $db->moveCollection('/db/from', '/db/some', 'to');
=cut

# the two params version is missing from the interface description, so
# we use a little work-around
sub moveCollection($$;$)
{   my ($self, $from, $tocoll, $subcoll) = @_;
    defined $subcoll
        or ($tocoll, $subcoll) = $tocoll =~ m! ^ (.*) / ([^/]+) $ !x;

    $self->{rpc}->moveCollection(string => $from, string => $tocoll
      , string => $subcoll);
}

=method describeCollection [COLLECTION], OPTIONS
Returns the RC and a HASH with details.  The details are the same as
returned with M<getCollectionDesc()>, excluding details about
documents.

=option  documents BOOLEAN
=default documents <false>

=example
  my ($rc, $descr) = $db->describeCollection($coll, documents => 1);
  $rc and die $rc;
  print Dumper $descr;  # Data::Dumper::Dumper
=cut

#T
sub describeCollection(;$%)
{   my $self = shift;
    my $coll = @_ % 2 ? shift : $self->{repository};
    my %args = @_;
    my ($rc, $data) = $args{documents}
      ? $self->{rpc}->getCollectionDesc(string => $coll)
      : $self->{rpc}->describeCollection(string => $coll);
    $rc==0 or return ($rc, $data);

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
    (0, $h);
}

=method subCollections [COLLECTION]
[non-API] Returns a list of sub-collections for this collection, based
on the results of M<describeCollection()>. The returned names are made
absolute.
=example
  my ($rc, @subs) = $db->subCollections($coll);
  $rc and die "$rc $subs[0]";
  print "@subs\n";
=cut

#T
sub subCollections(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    my ($rc, $data) = $_[0]->describeCollection($coll, documents => 0);
    $rc==0 or return ($rc, $data);
    (0, map { "$data->{name}/$_" } @{$data->{collections} || []});
}

=method collectionCreationDate [COLLECTION]
[non-API] Returns the date of the creation of the COLLECTION, by default
from the root.
=example
  my ($rc, $date) = $db->collectionCreationDate($coll);
  $rc and die "$rc $date";
  print $date;  # f.i. "2009-10-21T12:13:13Z"
=cut

#T
sub collectionCreationDate(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    $self->{rpc}->getCreationDate(string => $coll);
}

=method listResources [COLLECTION]
[non-API] Returns ... with all documents in the COLLECTION. Without
COLLECTION, it will list all documents in the whole repository.
=example
  my ($rc, @elems) = $db->listResources;
  $rc==0 or die "error: $elems[0] ($rc)";
=cut

#T
sub listResources(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    my ($rc, $details)
       = $self->{rpc}->getDocumentListing($coll ? (string => $coll) : ());
    $rc==0 or return ($rc, $details);
    ($rc, rpcarray_values $details);
}

=method reindexCollection COLLECTION
Reindex all documents in a certain collection.
=example
   my ($rc, $success) = $db->reindexCollection($name);
   die "error: $success ($rc)" if $rc;
   die "failed" unless $success;
=cut

#T
sub reindexCollection($)
{   my ($self, $coll) = @_;
    $self->{rpc}->reindexCollection(string => $coll);
}

=method removeCollection COLLECTION
Remove an entire collection from the database.
=example
   my ($rc, $success) = $db->removeCollection($name);
   die "error: $rc $success" if $rc;
   die "failed" unless $success;
=cut

#T
sub removeCollection($)
{   my ($self, $coll) = @_;
    $self->{rpc}->removeCollection(string => $coll);
}

#-----------------
=section Permissions

=method login USERNAME, [PASSWORD]
[non-API] Change the USERNAME (as known by ExistDB). When you specify
a non-existing USERNAME or a wrong PASSWORD, you will not get more data
from this connection.  The next request will tell.
=cut

#T
sub login($;$)
{   my ($self, $user, $password) = @_;
    $self->{user}     = $user;
    $self->{password} = defined $password ? $password : '';
    $self->{rpc}->headers->header(Authorization => 'Basic '
      . encode_base64("$user:$password", ''));
    (0);
}

=method listGroups
[non-API] list all defined groups.
Returns a vector.
=example
  my ($rc, @groups) = $db->listGroups;
  $rc==0 or die "$groups[0] ($rc)";
=cut

#T
sub listGroups()
{   my ($rc, $details) = shift->{rpc}->getGroups;
    $rc==0 or return ($rc, $details);
    (0, rpcarray_values $details);
}

=method describeResourcePermissions RESOURCE
[non-API] returns HASH with permission details about a RESOURCE>
=cut

#T
sub describeResourcePermissions($)
{   my ($rc, $details) = $_[0]->{rpc}->getPermissions(string => $_[1]);
    $rc==0 or return ($rc, $details);
    ($rc, struct_to_hash $details);
}

=method listDocumentPermissions [COLLECTION]
List the permissions for all resources in the COLLECTION
=cut

#T
sub listDocumentPermissions($)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    my ($rc, $details) = $_[0]->{rpc}->listDocumentPermissions(string => $coll);
    $rc==0 or return ($rc, $details);
    my $h = struct_to_hash $details;
    my %h;
    while( my ($k,$v) = each %$h)
    {   $h{$k} = [ rpcarray_values $v ];
    }
    (0, \%h);
}

=method describeUser USERNAME
[non-API] returns a HASH with user information.
=example
  my ($rc, $info) = $db->describeUser($username);
  $rc==0 or die "error: $info ($rc)";
  my @groups = @{$info->{groups}};
=cut

#T
sub describeUser($)
{   my ($self, $user) = @_;
    my ($rc, $details) = $self->{rpc}->getUser(string => $user);
    $rc==0 or return ($rc, $details);
    my $h = struct_to_hash $details;
    $h->{groups} = [ rpcarray_values $h->{groups} ];
    (0, $h);
}

=method listUsers
[non-API] Returns a LIST with all defined usernames.
=example
  my ($rc, @users) = $db->listUsers;
  $rc==0 or die "error $users[0] ($rc)";
=cut

#T
sub listUsers()
{   my ($rc, $details) = shift->{rpc}->getUsers;
    $rc==0 or return ($rc, $details);
    my %h;
    foreach my $user (rpcarray_values $details)
    {   my $u = struct_to_hash $user;
        $u->{groups} = [ rpcarray_values $u->{groups} ];
        $h{$u->{name}} = $u;
    }
    (0, \%h);
}

=method removeUser USERNAME
Returns true on success.
=cut

#T
sub removeUser($) { $_[0]->{rpc}->removeUser(string => $_[1]) }

=method setPermissions TARGET, PERMISSIONS, [USER, GROUP]
The TARGET which is addressed is either a resource or a collection.

The PERMISSIONS are specified either as an integer value or using a
modification string. The bit encoding of the integer value corresponds
to Unix conventions (with 'x' is replaced by 'update'). The modification
string has as syntax:
  [user|group|other]=[+|-][read|write|update][, ...]

=cut

sub setPermissions($$;$$)
{   my ($self, $target, $perms, $user, $group) = @_;

    my @chown = ($user && $group) ? (string => $user, string => $group) : ();
    $self->{rpc}->setPermissions(string => $target, @chown
       , ($perms =~ m/\D/ ? 'string' : 'int') => $perms);
}

=method setUser USER, PASSWORD, GROUPS, [HOME]
Modifies or creates a repository user.
The PASSWORD is plain-text password. GROUPS are specified as single
scalar or and ARRAY. The first group is the user's primary group.
=cut

#T
sub setUser($$$;$)
{   my ($self, $user, $password, $groups, $home) = @_;
    my @groups = ref $groups eq 'ARRAY' ? @$groups : $groups;

    $self->{rpc}->setUser(string => $user
       , string => md5_base64($password)
       , string => md5_hex("$user:exist:$password")
       , rpcarray_from(string => @groups)
       , ($home ? (string => $home) : ())
       );
}

=method describeCollectionPermissions [COLLECTION]
Returns the RC and a HASH which shows the permissions on the COLLECTION.
The output of the API is regorously rewritten to simplify implementation.

The HASH contains absolute collection names as keys, and then as values
a HASH with C<user>, C<group> and C<mode>.
=cut

#T
sub describeCollectionPermissions(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    my ($rc, $data) = $self->{rpc}->listCollectionPermissions(string => $coll);
    $rc==0 or return ($rc, $data);
    my $h = struct_to_hash $data;
    my %p;
    foreach my $relname (keys %$h)
    {  my %perms;
       @perms{ qw/user group mode/ } = rpcarray_values $h->{$relname};
       $p{"$coll/$relname"} = \%perms;
    }
    ($rc, \%p);
}

#-----------------
=section Resources

=method copyResource FROM, TOCOLL, TONAME
=example
  my ($rc, $success) = $db->copyResource(...);
=cut

### need two-arg version?
sub copyResource($$$)
{   my $self = shift;
    $self->{rpc}->copyResource(string=> $_[0], string=> $_[1], string=> $_[2]);
}

=method uniqueResourceName [COLLECTION]
Produces a random (and hopefully unique) resource-id (string) within
the COLLECTION.  The returned id looks something like C<fe7c6ea4.xml>.
=example
  my ($rc, $id) = $db->uniqueResourceName($coll);
=cut

#T
sub uniqueResourceName(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    $self->{rpc}->createResourceId(string => $coll);
}

=method describeResource RESOURCE
Returns details about a RESOURCE (which is a document or a binary).
=example
  my ($rc, $details) = $db->describeResource($resource);
=cut

sub describeResource($)
{   my ($self, $resource) = @_;
    my ($rc, $details) = $self->{rpc}->describeResource(string => $resource);
    $rc==0 or return ($rc, $details);
    ($rc, struct_to_hash $details);
}

=method countResources [COLLECTION]
[non-API] Returns the number of resources in the COLLECTION.
=example
  my ($rc, $count) = $db->countResources($collection);
=cut

#T
sub countResources(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    $self->{rpc}->getResourceCount(string => $coll);
}

=method moveResource FROM, TOCOLL, TONAME
=example
  my ($rc, $success) = $db->moveResource(...);
=cut

### two-params version needed?
sub moveResource($$$)
{   my $self = shift;
    $self->{rpc}->moveResource(string=> $_[0], string=> $_[1], string=> $_[2]);
}

=method getDocType DOCUMENT
Returns details about the DOCUMENT, the docname, public-id and system-id
as list of three.
=example
  my ($docname, $public, $system) = $db->getDocType($doc);
=cut

#T
sub getDocType($)
{   my ($rc, $details) = $_[0]->{rpc}->getDocType(string => $_[1]);
    $rc==0 or return ($rc, $details);
    ($rc, rpcarray_values $details);
}

=method setDocType DOCUMENT, TYPENAME, PUBLIC_ID, SYSTEM_ID
Add DOCTYPE information to a DOCUMENT.

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
    $self->{rpc}->setDocType(string => $doc
      , string => $name, string => $pub, string => $sys);
}

=method whoLockedResource RESOURCE
[non-API] Returns a username.
=cut

sub whoLockedResource($) {$_[0]->{rpc}->hasUserLock(string => $_[1]) }

=method unlockResource RESOURCE
Returns its success.
=cut

sub unlockResource($) {$_[0]->{rpc}->unlockResource(string => $_[1]) }

=method lockResource RESOURCE, [USERNAME]
=cut

sub lockResource($;$)
{   my ($self, $resource, $user) = @_;
    $user ||= $self->{user}
        or report ERROR => "no default username set nor specified for lock";
    $self->{rpc}->lockResource(string => $resource, string => $user);
}

=method removeResource DOCNAME
[non-API] remove a DOCument from the repository by NAME.  This method's name
is more consistent than the official API name C<remove()>.
=cut

sub removeResource($) { $_[0]->{rpc}->remove(string => $_[1]) }

#--------------------
=subsection Download documents

=method downloadDocument RESOURCE, FORMAT
Returns a document as byte array.
=cut

#T
sub downloadDocument($@)
{   my $self = shift;
    my ($rc, $chunk) = $self->getDocumentData(@_);
    $rc==0 or return ($rc, $chunk);

    my @data = \$chunk->{data};
    while($rc==0 && $chunk->{offset})
    {   ($rc, $chunk) = $chunk->{'supports-long-offset'}
        ? $self->getNextExtendedChunk($chunk->{handle}, $chunk->{offset})
        : $self->getNextChunk($chunk->{handle}, $chunk->{offset});
        $rc or push @data, \$chunk->{data};
    }
    $rc==0 or return ($rc, $chunk);

    (0, join '', map {$$_} @data);
}

# does this also work for binary resources?

=method listResourceTimestamps RESOURCE
[non-API] Returns the creation and modification dates.
=example
   my ($rc, $created, $modified) = $db->listResourceTimestamps($resource);
   $rc==0 or die "error: $created ($rc)";
=cut

sub listResourceTimestamps($)
{   my ($rc, $vector) = $_[0]->{rpc}->getTimestamps(string => $_[1]);
    $rc==0 or return ($rc, $vector);
    (0, rpcarray_values $vector);
}

#-----------------
=subsection Upload documents

=method uploadDocument RESOURCE, DOCUMENT, OPTIONS
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
    my $replace = $args{replace};
    my $mime    = $args{mime_type} || 'text/xml';

    # Send file in chunks
    my $to_sent = length $doc;
    my $sent    = 0;
    my $tmp;

    while($sent < $to_sent)
    {   (my $rc, $tmp) = $self->upload($tmp, substr($doc, $sent, $chunks));
        $rc==0 or return ($rc, $tmp);
        $sent += $chunks;
    }
    $self->parseLocal($tmp, $resource, $replace, $mime, @dates);
}

=method downloadBinary RESOURCE
[non-API] Get the bytes of a binary file from the server.
=example
  my ($rc, $bytes) = $db->downloadBinary($resource);
=cut

sub downloadBinary($) { $_[0]->{rpc}->getBinaryResource(string => $_[1]) }

=method uploadBinary RESOURCE, BYTES, MIME, REPLACE, [CREATED, MODIFIED]
[non-API] The BYTES can be passed as string or better as string reference.
=example
  my ($rc, $ok) = $db->storeBinaryResource($name, $bytes, 'text/html', 1);
=cut

sub uploadBinary($$$$;$$)
{   my ($self, $resource, $bytes, $mime, $replace, $created, $modified) = @_;
    
    $self->{rpc}->storeBinary
      ( base64 => (ref $bytes ? $$bytes : $bytes)
      , string => $resource, string => $mime, boolean => $replace
      , _date_options($created, $modified)
      );
}

#-----------------
=section Queries

=subsection Compiled queries

=method compile QUERY, FORMAT
Returns a HASH.
=cut

#T
### compile doesn't return anything
sub compile($@)
{   my ($self, $query) = (shift, shift);
    my ($rc, $details) = $self->{rpc}->compile(base64 => $query
      , $self->_format(@_));
    $rc==0 or return ($rc, $details);
    (0, struct_to_hash $details);
}

=method describeCompile QUERY, FORMAT
[non-API] Returns a string which contains the diagnostics of compiling
the query.
=cut

#T
# printDiagnostics should accept a base64
sub describeCompile($@)
{   my ($self, $query) = (shift, shift);
    $self->{rpc}->printDiagnostics(string => $query, $self->_format(@_));
}

=method execute QUERYHANDLE, FORMAT
Returns a HASH.
=cut

sub execute($@)
{   my ($self, $handle) = (shift, shift);
    my ($rc, $details)  = $self->{rpc}->execute(string => $handle
      , $self->_format(@_));
    $rc==0 or return ($rc, $details);
    (0, struct_to_hash $details);
}

#-----------------
=subsection Query returns result as set

=method executeQuery QUERY, [ENCODING], [FORMAT]
Run the QUERY given in the specified ENCODING.  Returned is
only an identifier to the result.

=example
   my ($rc1, $set)   = $db->executeQuery($query);
   my ($rc2, $count) = $db->numberOfResults($set);
   my ($rc3, @data)  = $db->retrieveResults($set);
   $db->releaseResults($set);
=cut

sub executeQuery($@)
{   my ($self, $query) = @_;
    my @enc = @_ % 2 ? (string => shift) : ();
    $self->{rpc}->executeQuery(base64 => $query, @enc, $self->_format(@_));
}

=method numberOfResults RESULTSET
[non-API] Returns the number of answers in the RESULT set of a query.
Replaces C<getHits()>.
=cut

sub numberOfResults($) { $_[0]->{rpc}->getHits(int => $_[1]) }

=method describeResultSet RESULTSET
[non-API] Retrieve a summary of the result set identified by it's
result-set-id. This method returns a HASH with simple values
C<queryTime> (milli-seconds) and C<hits> (number of results).
Besides, it contains complex structures C<documents> and C<doctypes>.
=cut

#T
# what does "docid" mean?
sub describeResultSet($)
{   my ($rc, $details) = $_[0]->{rpc}->querySummary(int => $_[1]);
    $rc==0 or return ($rc, $details);
    my $results = struct_to_hash $details;
    if(my $docs = delete $results->{documents})
    {   my @docs;
        foreach my $result (rpcarray_values $docs)
        {   my ($name, $id, $hits) = rpcarray_values $result;
            push @docs, { name => $name, docid => $id, hits => $hits };
        }
        $results->{documents} = \@docs;
    }
    if(my $types = delete $results->{doctypes})
    {   my @types;
        foreach my $result (rpcarray_values $types)
        {   my ($class, $hits) = rpcarray_values $result;
            push @types, { class => $class, hits => $hits };
        }
        $results->{doctypes} = \@types;
    }
    ($rc, $results);
}

=method releaseResultSet RESULTSET, [PARAMS]
[non-API] Give-up on the RESULTSET on the server.
=cut

#### what kind of params from %args?
#### releaseQueryResult(int $resultid, int $hash)   INT?
sub releaseResultSet($@)
{   my ($self, $results, %args) = @_;
    $self->{rpc}->releaseQueryResult(int => $results, int => 0);
}

=method retrieveResult RESULTSET, POS, [FORMAT]
[non-API] retrieve a single result from the RESULT-SET.
Replaces M<retrieve()> and M<retrieveFirstChunk()>.
=cut

sub retrieveResult($$@)
{   my ($self, $set, $pos) = (shift, shift, shift);
    my ($rc, $bytes)
       = $self->{rpc}->retrieve(int => $set, int => $pos, $self->_format(@_));
    $rc==0 or return ($rc, $bytes);
    (0, $self->schemas->decodeXML($bytes));
}

=method retrieveResults RESULTSET, [FORMAT]
Replaces M<retrieveAll()> and M<retrieveAllFirstChunk()>.
=cut

# hitCount where describeResultSet() uses 'hits'
#T
sub retrieveResults($@)
{   my ($self, $set) = (shift, shift);
    my ($rc, $bytes) = $self->{rpc}->retrieveAll(int => $set
      , $self->_format(@_));
    $rc==0 or return ($rc, $bytes);
    (0, $self->schemas->decodeXML($bytes));
}

#-----------------
=subsection Query returns result

=method query QUERY, LIMIT, [FIRST], [FORMAT]
Returns a document of the collected results.

This method is deprecated according to the java description, in favor of
M<executeQuery()>, however often used for its simplicity.
=cut

#T
# Vector query() is given as alternative but does not exist.
sub query($$$@)
{   my ($self, $query, $limit) = (shift, shift, shift);
    my $first = @_ % 2 ? shift : 1;
    my ($rc, $bytes) = $self->{rpc}->query(string => $query, int => $limit
       , int => $first, $self->_format(@_));
    $rc==0 or return ($rc, $bytes);
    (0, $self->schemas->decodeXML($bytes));
}

=method queryXPath XPATH, DOCNAME, NODE_ID, OPTIONS
When DOCUMENT is defined, then the search is limited to that document,
optionally further restricted to the NODE with the indicated ID.

=example
  my ($rc, $h) = $db->queryXPath($xpath, undef, undef);
=cut

sub queryXPath($$$@)
{   my ($self, $xpath, $doc, $node) = splice @_, 0, 4;
    my @args = (base64 => $xpath);
    push @args, string => $doc, string => (defined $node ? $node : '')
        if defined $doc;
    my ($rc, $data) = $self->{rpc}->queryP(@args, $self->_format(@_));
    $rc==0 or return ($rc, $data);

    my $h = struct_to_hash $data;
    my @r;
    foreach (rpcarray_values $h->{results})
    {   my ($doc, $loc) = rpcarray_values $_;
        push @r, { document => $doc, node_id => $loc };
    }
    $h->{results} = \@r;

    (0, $h);
}
 
#-----------------
=subsection Simple node queries

=method retrieveDocumentNode DOCUMENT, NODEID, [FORMAT]
[non-API] Collect one node from a certain document. Doesn't matter
how large: this method will always work (by always using chunks).
=cut

sub retrieveDocumentNode($$@)
{   my $self = shift;
    my ($rc, $chunk) = $self->{rpc}->retrieveFirstChunk(@_);

    my @data = \$chunk->{data};
    while($rc==0 && $chunk->{offset})
    {   ($rc, $chunk) = $chunk->{'supports-long-offset'}
        ? $self->getNextExtendedChunk($chunk->{handle}, $chunk->{offset})
        : $self->getNextChunk($chunk->{handle}, $chunk->{offset});
        $rc or push @data, \$chunk->{data};
    }
    $rc==0 or return ($rc, $chunk);

    (0, $self->schemas->decodeXML(join '', map {$$_} @data));
}

#-----------------
=subsection Modify document content

=method updateResource RESOURCE, XUPDATE, [ENCODING]
=example
  my ($rc, $some_int) = $db->updateResource($resource, $xupdate);
=cut

### What does the returned int mean?
sub updateResource($$;$)
{   my ($self, $resource, $xupdate, $encoding) = @_;
    $self->{rpc}->xupdateResource(string => $resource, string => $xupdate
      , ($encoding ? (string => $encoding) : ()));
}

### What does the returned int mean?
### Does this update the collection configuration?
=method updateCollection COLLECTION, XUPDATE
[non-API]
=example
  my ($rc, $some_int) = $db->updateCollection($coll, $xupdate);
=cut

sub updateCollection($$)
{   $_[0]->{rpc}->xupdate(string => $_[1], string => $_[2]);
}

#-----------------
=section Indexing

=method scanIndexTerms COLLECTION, BEGIN, END, RECURSIVE

or C<< $db->scanIndexTerms(XPATH, BEGIN, END) >>.

=examples
  my ($rc, $details) = $db->scanIndexTerms($xpath, $begin, $end);
  my ($rc, $details) = $db->scanIndexTerms($coll, $begin, $end, $recurse);
=cut

sub scanIndexTerms($$$;$)
{   my $self = shift;
     my ($rc, $details);
    if(@_==4)
    {   my ($coll, $begin, $end, $recurse) = @_;
        ($rc, $details) = $self->{rpc}->scanIndexTerms(string => $coll
          , string => $begin, string => $end, boolean => $recurse);
    }
    else
    {   my ($xpath, $begin, $end) = @_;
### no idea what xpath means here.
        ($rc, $details) = $self->{rpc}->scanIndexTerms(string => $xpath
          , string => $begin, string => $end);
    }

    $rc==0 or return ($rc, $details);
    (0, rpcarray_values $details);
}

=method getIndexedElements COLLECTION, RECURSIVE
=cut

sub getIndexedElements($$)
{   my ($self, $coll, $recurse) = @_;
    my ($rc, $details) = $self->{rpc}->getIndexedElements(string => $coll
       , boolean => $recurse);
    $rc==0 or return ($rc, $details);
### cleanup Vector $details. Per element:
#  1. name of the element
#  2. optional namespace URI
#  3. optional namespace prefix
#  4. number of occurrences of this element as an integer value

    (0, rpcarray_values $details);
}


#-----------------
=section Helpers

=method schemas
Returns the M<XML::eXistDB> object which contains all eXistDB specific
schema information. At first call, the object will get created for you.
Once created, you'll always get the same.
=cut

sub schemas()
{   my $self = shift;
    return $self->{schemas} if $self->{schemas};

    # This will load a lot of XML::Compile::* modules. Therefore, we
    # do this lazy: only when needed.
    eval "require XML::eXistDB";
    panic $@ if $@;

    $self->{schemas} = XML::eXistDB->new;
}

=method trace
Returns the trace information from the last command executed over RPC. Nearly
all methods in this class only perform one RPC call. You can find the timings,
http request, and http response in the returned HASH.
=cut

sub trace() { shift->{rpc}->trace }

#----------------
=section Please avoid
Some standard API methods have gotten more powerful alternatives.  Please
avoid using the methods described in this section (although they do work)

=subsection Please avoid: collections

=method getCollectionDesc [COLLECTION]
Please use M<describeCollection()> with option C<< documents => 0 >>.
=cut

#T
sub getCollectionDesc(;$)
{   my ($self, $coll) = @_;
    $coll ||= $self->{repository};
    $self->describeCollection($coll, documents => 1);
}

#---------
=subsection Please avoid: download documents

=method getDocument RESOURCE, FORMAT|(ENCODING, PRETTY, STYLE)
Please use M<downloadDocument()>.  Either specify FORMAT parameters
(a list of pairs), or three arguments.  In the latter case, the
STYLE must be present but may be C<undef>.  STYLE refers to a
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
    $self->{rpc}->getDocument(string => $resource, @args);
}

=method getDocumentAsString RESOURCE, FORMAT|(ENCODING, PRETTY, STYLE)
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
    $self->{rpc}->getDocumentAsString(string => $resource, @args);
}

=method getDocumentData RESOURCE, FORMAT
Please use M<downloadDocument()>.
Retrieve the specified document, but limit the number of bytes
transmitted to avoid memory shortage on the server. The size of the
chunks is controled by the server.  Returned is a HASH.

When the returned HASH contains C<supports-long-offset>, then get the
next Chunk with M<getNextExtendedChunk()> otherwise use M<getNextChunk()>.

=example
   my ($rc, $chunk) = $db->getDocumentData($resource);
   my $doc = $chunk->{data};
   while($rc==0 && $chunk->{offset}!=0)
   {   ($rc, $chunk) = $chunk->{'supports-long-offset'}
       ? $db->getNextExtendedChunk($chunk->{handle}, $chunk->{offset})
       : $db->getNextChunk($chunk->{handle}, $chunk->{offset});
       $rc==0 and $doc .= $chunk->{data};
   }
   $rc==0 or die "error: $chunk ($rc)";
       
=cut

sub getDocumentData($@)
{   my ($self, $resource) = (shift, shift);
    my ($rc, $details) = $self->{rpc}->getDocumentData(string => $resource
      , $self->_format(@_));
    $rc==0 or return ($rc, $details);
    (0, struct_to_hash $details);
}

=method getNextChunk TMPNAME, OFFSET
Collect the next chunk, initiated with a M<getDocumentData()>. The file
is limited to 2GB.
=cut

sub getNextChunk($$)
{   my ($self, $handle, $offset) = @_;
    my ($rc, $details)
      = $self->{rpc}->getNextChunk(string => $handle, int => $offset);
    $rc==0 or return ($rc, $details);
    (0, struct_to_hash $details);
}

=method getNextExtendedChunk TMPNAME, OFFSET
Collect the next chunk, initiated with a M<getDocumentData()>. This method
can only be used with servers which run an eXist which supports long files.
=cut

sub getNextExtendedChunk($$)
{   my ($self, $handle, $offset) = @_;
    my ($rc, $details)
      = $self->{rpc}->getNextChunk(string => $handle, string => $offset);
    $rc==0 or return ($rc, $details);
    (0, struct_to_hash $details);
}

#---------
=subsection Please avoid: uploading documents

=method parse DOCUMENT, RESOURCE, [REPLACE, [CREATED, MODIFIED]]
Please use M<uploadDocument()>.
Store the DOCUMENT of a document under the RESOURCE name into the
repository. When REPLACE is true, it will overwrite an existing document
when it exists.

The DATA can be a string containing XML or M<XML::LibXML::Document>.
=cut

sub parse($$;$$$)
{   my ($self, $data, $resource, $replace, $created, $modified) = @_;
   
    $self->{rpc}->parse
      ( base64 => $self->_document($data)
      , string => $resource, int => ($replace ? 1 : 0)
      , _date_options($created, $modified)
      );
}

=method parseLocal TEMPNAME, RESOURCE, REPLACE, MIME, [CREATED, MODIFIED]
Please use M<uploadDocument()>.
Put the content of document which was just oploaded to the server under some
TEMPNAME (received from M<upload()>), as RESOURCE in the database.

NB: B<Local> means "server local", which is remote for us as clients.
=cut

sub parseLocal($$$$;$$)
{   my ($self, $fn, $resource, $replace, $mime, $created, $modified) = @_;
   
    $self->{rpc}->parseLocal
      ( string => $fn, string => $resource, boolean => $replace
      , string => $mime, _date_options($created, $modified)
      );
}

=method parseLocalExt TEMPNAME, RESOURCE, REPLACE, MIME, ISXML, [CREATED, MODIFIED]
Please use M<uploadDocument()>.
Put the content of document which was just oploaded with M<upload()> to
the server under some TEMPNAME (received from M<upload()>) as RESOURCE
in the database. Like M<parseLocal()>, but with extra C<ISXML> boolean,
to indicate that the object is XML, where the server does not know that
from the mime-type.

NB: B<Local> means "server local", which is remote for us as clients.
=cut

sub parseLocalExt($$$$;$$)
{   my ($self, $fn, $res, $replace, $mime, $is_xml, $created, $modified) = @_;
   
    $self->{rpc}->parseLocal
      ( string => $fn, string => $res, boolean => $replace
      , string => $mime, boolean => $is_xml
      , _date_options($created, $modified)
      );
};

=method upload [TEMPNAME], CHUNK
Please use M<uploadDocument()>.
Upload a document in parts to the server. The first upload will give
you the TEMPoraryNAME for the object. You may leave that name out or
explicitly state C<undef> at that first call.  When all data is uploaded,
call M<parseLocal()> or M<parseLocalExt()>.

=example
   # start uploading
   my ($rc1, $tmp)  = $db->upload(undef, substr($data, 0, 999));
   my ($rc1, $tmp)  = $db->upload(substr($data, 0, 999));  # same

   # send more chunks
   my ($rc2, undef) = $db->upload($tmp,  substr($data, 1000));

   # insert the document in the database
   my ($rc3, $ok)   = $db->parseLocal($tmp, '/db/file.xml', 0, 'text/xml')
      if $rc1==0 && $rc2==0;
=cut

sub upload($;$)
{   my $self = shift;
    my $tmp  = @_ == 2 ? shift : undef;
    $self->{rpc}->upload(string => (defined $tmp ? $tmp : '')
       , base64 => $_[0], int => length($_[0]));
}

=method uploadCompressed [TEMPNAME], CHUNK
Please use M<uploadDocument()>.
Like M<upload()>, although the chunks are part of a compressed file.
=cut

sub uploadCompressed($;$)
{   my $self = shift;
    my $tmp  = @_ == 3 ? shift : undef;

### Not sure whether each chunk is compressed separately or the
### data is compressed as a whole.
    $self->{rpc}->uploadCompressed
       ( (defined $tmp ? (string => $tmp) : ())
       , base64 => $_[0], int => length($_[1]));
}

=method storeBinary BYTES, RESOURCE, MIME, REPLACE, [CREATED, MODIFIED]
Please use M<uploadBinary()>.
=cut

sub storeBinary($$$$;$$) { $_[0]->uploadBinary( @_[2, 1, 3, 4, 5, 6] ) }

#-------
=subsection Please avoid: simple node queries

=method retrieveFirstChunk (DOCUMENT, NODEID)|(RESULTSET, POS), [FORMAT]
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
    my $format = $self->_format(@_);
    my ($rc, $details) = $self->{rpc}->retrieveFirstChunk(@args, $format);
    ($rc, $rc==0 ? $details : struct_to_hash $details);
}

#------------------
=subsection Please avoid: collect query results

=method retrieve (DOCUMENT, NODEID)|(RESULTSET, POS), [FORMAT]
Please use M<retrieveResult()> or M<retrieveDocumentNode()>.
=cut

sub retrieve($$@)
{   my $self = shift;
    my @args = $_[0] =~ m/\D/
             ? (string => shift, string => shift)
             : (int => shift, int => shift);

    my ($rc, $bytes) = $self->{rpc}->retrieve(@args, $self->_format(@_));
    $rc==0 or return ($rc, $bytes);
    (0, $self->schemas->decodeXML($bytes));
}

=method retrieveAll RESULTSET, [FORMAT]
Please use M<retrieveResults()>.
=cut

sub retrieveAll($$@)
{   my ($self, $set) = (shift, shift);
    my ($rc, $bytes) = $self->{rpc}->retrieveAll(int => $set
      , $self->_format(@_));
    $rc==0 or return ($rc, $bytes);
    (0, $self->schemas->decodeXML($bytes));
}

=method retrieveAllFirstChunk RESULTSET, [FORMAT]
Please use M<retrieveResults()>.
=cut

sub retrieveAllFirstChunk($$@)
{   my ($self, $result) = (shift, shift);
    my ($rc, $details)  = $self->{rpc}->retrieveAllFirstChunk(int => $result
      , $self->_format(@_));
    $rc==0 or return ($rc, $details);
    (0, struct_to_hash $details);
}

=method isValidDocument DOCUMENT
Returns true when the DOCUMENT (inside the database) is validated as
correct.
=cut

sub isValidDocument($)
{   my ($self, $doc) = (shift, shift);
    $self->{rpc}->isValid(string => $doc);
}

=method initiateBackup DIRECTORY
Trigger the backup task to write to the DIRECTORY. Returns true, always,
but that does not mean success: the initiation will succeed.
=cut

sub initiateBackup($)
{   my ($self, $s) = (shift, shift);
    $self->{rpc}->dataBackup($s);
}

=method getDocumentChunked DOCNAME, OPTIONS
Please use M<downloadDocument()>
=example
   my ($rc, $handle, $total_length) = $db->getDocumentChuncked($doc);
   my $xml = $db->getDocumentNextChunk($handle, 0, $total_length-1);
=cut

sub getDocumentChunked($@)
{   my ($self, $doc) = (shift, shift);
    my ($rc, $data) = $self->{rpc}->getDocumentChunk(string => $doc);
    $rc==0 or return ($rc, $data);
    (0, rpcarray_values $data);
}

=method getDocumentNextChunk HANDLE, START, LENGTH
=cut

sub getDocumentNextChunk($$$)
{   my ($self, $handle, $start, $len) = @_;
    $self->{rpc}->getDocumentChunck(string => $handle
      , int => $start, int => $len);
}

=method retrieveAsString DOCUMENT, NODEID, OPTIONS
=cut

sub retrieveAsString($$@)
{   my ($self, $doc, $node) = (shift, shift, shift);
    $self->{rpc}->retrieveAsString(string => $doc, string => $node
      , $self->_format(@_));
}

#----------------
=section Renamed methods
Quite a number of API methods have been renamed to be more consistent
with other names.  Using the new names should improve readibility. The
original names are still available:

  -- xml-rpc name              -- replacement name
  createResourceId          => uniqueResourceName
  dataBackup                => initiateBackup
  getBinaryResource         => downloadBinary
  getCreationDate           => collectionCreationDate
  getDocumentListing        => listResources
  getGroups                 => listGroups
  getHits                   => numberOfResults
  getPermissions            => describeResourcePermissions
  getResourceCount          => countResources
  getTimestamps             => listResourceTimestamps
  getUser                   => describeUser
  getUsers                  => listUsers
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
*getGroups = \&listGroups;
*getHits = \&numberOfResults;
*getPermissions = \&describeResourcePermissions;
*getResourceCount = \&countResources;
*getTimestamps = \&listResourceTimestamps;
*getUser   = \&describeUser;
*getUsers  = \&listUsers;
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

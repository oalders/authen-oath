#!perl -T

use strict;
use warnings;
use Test::More;

BEGIN {
    plan skip_all => "Author tests not required for installation"
        unless $ENV{RELEASE_TESTING};
}

use Test::Needs { 'Test::CheckManifest' => '0.9' };

Test::CheckManifest->import;
ok_manifest();

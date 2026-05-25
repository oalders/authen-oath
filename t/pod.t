#!perl -T

use strict;
use warnings;
use Test::More;
use Test::Needs { 'Test::Pod' => '1.22' };

Test::Pod->import;
all_pod_files_ok();

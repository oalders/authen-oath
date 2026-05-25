use strict;
use warnings;
use Test::More;
use Test::Needs {
    'Pod::Coverage'       => '0.18',
    'Test::Pod::Coverage' => '1.08',
};

Test::Pod::Coverage->import;
all_pod_coverage_ok();

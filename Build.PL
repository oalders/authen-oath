#!/usr/bin/perl
################################################################################
# $Id: Build.PL 3 2010-05-25 16:04:32Z v89326 $
# $URL: file:///S:/svn/Authen-OATH/trunk/Build.PL $
################################################################################
#
# Title:   Build.PL
# Author:  Kurt Kincaid
# VERSION: 1.0.0
#
################################################################################

use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name       => 'Authen::OATH',
    license           => 'perl',
    dist_author       => q{Kurt Kincaid <kurt.kincaid@gmail.com>},
    dist_version_from => 'lib/Authen/OATH.pm',
    build_requires    => {
        'Test::More'   => 0,
        'Test::Simple' => 0,
        'Moose'        => 0,
        'Math::BigInt' => 0,
        'Digest::HMAC' => 0,
        'Digest::SHA1' => 0,
    },
    add_to_cleanup     => [ 'Authen-OATH-*' ],
    create_makefile_pl => 'traditional',
);

$builder->create_build_script();

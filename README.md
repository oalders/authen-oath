# NAME

Authen::OATH - OATH One Time Passwords

[![Build Status](https://travis-ci.org/oalders/authen-oath.png?branch=master)](https://travis-ci.org/oalders/authen-oath)

# VERSION

version 0.000001

# SYNOPSIS

Implementation of the HOTP and TOTP One Time Password algorithms
as defined by OATH (http://www.openauthentication.org)

All necessary parameters are set by default, though these can be
overridden. Both totp() and htop() have passed all of the test
vectors defined in the RFC documents for TOTP and HOTP.

totp() and hotp() both default to returning 6 digits and using SHA1.
As such, both can be called by passing only the secret key and a
valid OTP will be returned.

    use Authen::OATH;

    my $oath = Authen::OATH->new();
    my $totp = $oath->totp( "MySecretPassword" );
    my $hotp = $oath->hotp( "MyOtherSecretPassword" );

Parameters may be overridden when creating the new object:

    my $oath = Authen::OATH->new( 'digits' => 8 );

The three parameters are "digits", "digest", and "timestep."
Timestep only applies to the totp() function.

While strictly speaking this is outside the specifications of
HOTP and TOTP, you can specify digests other than SHA1. For example:

    my $oath = Authen::OATH->new( "digits" => 10,
                                  "digest" => "Digest::MD6"
    );

# SUBROUTINES/METHODS

## totp

    my $otp = $oath->totp( $secret [, $manual_time ] );

Manual time is an optional parameter. If it is not passed, the current
time is used. This is useful for testing purposes.

## hotp

    my $opt = $oath->hotp( $secret, $counter );

Both parameters are required.

## \_process

This is an internal routine and is never called directly.

# BUGS

Please report any bugs or feature requests to `bug-authen-totp at rt.cpan.org`, or through
the web interface at [http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Authen-OATH](http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Authen-OATH).  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.

# SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Authen::OATH

You can also look for information at:

- RT: CPAN's request tracker

    [http://rt.cpan.org/NoAuth/Bugs.html?Dist=Authen-OATH](http://rt.cpan.org/NoAuth/Bugs.html?Dist=Authen-OATH)

- AnnoCPAN: Annotated CPAN documentation

    [http://annocpan.org/dist/Authen-OATH](http://annocpan.org/dist/Authen-OATH)

- CPAN Ratings

    [http://cpanratings.perl.org/d/Authen-OATH](http://cpanratings.perl.org/d/Authen-OATH)

- Search CPAN

    [http://search.cpan.org/dist/Authen-OATH/](http://search.cpan.org/dist/Authen-OATH/)

# AUTHOR

Kurt Kincaid <kurt.kincaid@gmail.com>

# COPYRIGHT AND LICENSE

This software is copyright (c) 2010 by Kurt Kincaid.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

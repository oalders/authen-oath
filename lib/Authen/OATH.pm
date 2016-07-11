package Authen::OATH;

use warnings;
use strict;

use Digest::HMAC;
use Math::BigInt;
use Moose;

has 'digits' => (
    'is'      => 'rw',
    'isa'     => 'Int',
    'default' => 6
);

has 'digest' => (
    'is'      => 'rw',
    'isa'     => 'Str',
    'default' => 'Digest::SHA1'
);

has 'timestep' => (
    'is'      => 'rw',
    'isa'     => 'Int',
    'default' => 30
);

=head1 NAME

Authen::OATH - OATH One Time Passwords

=head1 VERSION

Version 1.0.0

=cut

our $VERSION = "1.0.0";

=head1 SYNOPSIS

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

=head1 SUBROUTINES/METHODS

=head2 totp

    my $otp = $oath->totp( $secret [, $manual_time ] );
    
Manual time is an optional parameter. If it is not passed, the current 
time is used. This is useful for testing purposes.

=cut

sub totp {
    my ( $self, $secret, $manual_time ) = @_;
    $secret = join( "", map chr( hex() ), $secret =~ /(..)/g )
      if $secret =~ /^[a-fA-F0-9]{32,}$/;
    my $mod = $self->{ 'digest' };
    if ( eval "require $mod" ) {
        $mod->import();
    }
    my $time = $manual_time || time();
    my $T = Math::BigInt->new( int( $time / $self->{ 'timestep' } ) );
    die "Must request at least 6 digits" if $self->{ 'digits' } < 6;
    ( my $hex = $T->as_hex ) =~ s/^0x(.*)/"0"x(16 - length $1) . $1/e;
    my $bin_code = join( "", map chr hex, $hex =~ /(..)/g );
    my $otp = _process( $self, $secret, $bin_code );
    return $otp;
}

=head2 hotp

    my $opt = $oath->hotp( $secret, $counter );
    
Both parameters are required.

=cut

sub hotp {
    my ( $self, $secret, $c ) = @_;
    $secret = join( "", map chr( hex() ), $secret =~ /(..)/g )
      if $secret =~ /^[a-fA-F0-9]{32,}$/;
    my $mod = $self->{ 'digest' };
    if ( eval "require $mod" ) {
        $mod->import();
    }
    $c = Math::BigInt->new( $c );
    die "Must request at least 6 digits" if $self->{ 'digits' } < 6;
    ( my $hex = $c->as_hex ) =~ s/^0x(.*)/"0"x(16 - length $1) . $1/e;
    my $bin_code = join( "", map chr hex, $hex =~ /(..)/g );
    my $otp = _process( $self, $secret, $bin_code );
    return $otp;
}

=head2 _process

This is an internal routine and is never called directly.

=cut

sub _process {
    my ( $self, $secret, $bin_code ) = @_;
    my $hmac = Digest::HMAC->new( $secret, $self->{ 'digest' } );
    $hmac->add( $bin_code );
    my $hash   = $hmac->digest();
    my $offset = hex substr unpack( "H*" => $hash ), -1;
    my $dt     = unpack "N" => substr $hash, $offset, 4;
    $dt &= 0x7fffffff;
    $dt = Math::BigInt->new( $dt );
    my $modulus = 10 ** $self->{ 'digits' };

    if ( $self->{ 'digits' } < 10 ) {
        return sprintf( "%0$self->{ 'digits' }d", $dt->bmod( $modulus ) );
    }
    else {
        return $dt->bmod( $modulus );
    }

}

=head1 AUTHOR

Kurt Kincaid, C<< <kurt.kincaid at gmail.com> >>

=head1 BUGS

Please report any bugs or feature requests to C<bug-authen-totp at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Authen-OATH>.  I will be notified, and then you'll
automatically be notified of progress on your bug as I make changes.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Authen::OATH


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Authen-OATH>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Authen-OATH>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Authen-OATH>

=item * Search CPAN

L<http://search.cpan.org/dist/Authen-OATH/>

=back


=head1 ACKNOWLEDGEMENTS


=head1 LICENSE AND COPYRIGHT

Copyright 2010 Kurt Kincaid.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

1;    # End of Authen::OATH

################################################################################
# EOF

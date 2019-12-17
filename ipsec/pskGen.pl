#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long::Descriptive;
use Data::Dumper::Simple;
use NetAddr::IP;

my ($opt, $usage) = describe_options(
	'%c %o',
	[ 'help|h', "help, print usage", ],
	[ 'verbose|v', "verbose"],
	
);


sub pskGen {
    my $l = shift;
    my $r = shift;
    my $x = `openssl rand -base64 $l`;
    my $str = '';
    for ( my $i=0; $i<$l; $i++) {
        my $c = ord (substr $x, $i, 1);
        if ( ($c>47 && $c<58)  || ($c>64 && $c<91) || ($c>96 && $c<122) )
        {
          $str .= substr $x, $i, 1;
          $r=$r-1;
          if ( $r == 0 ) {
            return $str;
            }
        }
    }
}

for ( my $i=0; $i<20; $i++) {

	printf pskGen(1024,64) . "\n";
	
}
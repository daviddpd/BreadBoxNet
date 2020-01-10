#!/usr/bin/perl

# Simple script to inspect the Perl objects when 
# parsing a YAML file.

use strict;
use warnings;

use Getopt::Long::Descriptive;
use Data::Dumper::Simple;
use NetAddr::IP;

use YAML;
my ($opt, $usage) = describe_options(
	'%c %o',
	[ 'help|h', "help, print usage", ],
	[ 'verbose|v', "verbose"],
	[ 'file|f=s', "a yaml file", { required => 1 } ],	
	
);
print($usage->text), exit if $opt->help;

sub readFile {
	my $filename = shift;
	my $buffer;
	my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($filename);
	open FHX, "<$filename";
	read (FHX,$buffer,$size);
	close FHX;
	return $buffer;
}

my $configstr = readFile ( $opt->{'file'} ) ;
my $config  = Load($configstr);
print Dumper ( $config );

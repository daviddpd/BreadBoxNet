#!perl

use strict;
use warnings;
use Data::Dumper::Simple;
use Getopt::Long::Descriptive;
use NetAddr::IP;
use YAML;

my ($opt, $usage) = describe_options(
	'%c %o',
	[ 'help|h', "help, print usage", ],
	[ 'verbose|v', "verbose"],
	[ 'ipfile|f=s', "file with all the ips mappings, flat text, auto detectes via extentation yaml files - .yml/.yaml", { required => 1 } ],
#	[ 'outdir|o=s', "Output Directory", { required => 1 } ],
	
);
sub readFile {
	my $filename = shift;
	my $buffer;
	my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($filename);
	open FHX, "<$filename";
	read (FHX,$buffer,$size);
	close FHX;
	return $buffer;
}

sub parseIpFile_yaml {
	my $filename = shift;
	my $buffer = readFile($filename);
	my $config  = Load($buffer);
	my @bgp;

	print Dumper ( $config );
	return $config;

}

my $c = parseIpFile_yaml($opt->ipfile);

my $fields_text="ip;site;vlan;net;BGP_NEIGHBOR;BGP_LOCAL;ASN_NEIGHBOR;ASNPLUS;ASNINC;ASN;SRVNET1;SRVMED1;SRVIP1;SRVNET2;SRVMED2;SRVIP2;SRVNET3;SRVMED3;SRVIP3";
my $data_text="
10.20.0.2;stl;1021;172.31.10.0/30;172.31.10.1;172.31.10.2;65000;64000;10;64010;10.69.1.0/24;1;10.69.1.1;10.69.2.0/24;3;10.69.2.1;10.69.3.0/24;2;10.69.3.1
10.20.0.3;stl;1021;172.31.10.4/30;172.31.10.5;172.31.10.6;65000;64000;20;64020;10.69.1.0/24;2;10.69.1.1;10.69.2.0/24;1;10.69.2.1;10.69.3.0/24;3;10.69.3.1
10.20.0.4;stl;1021;172.31.10.8/30;172.31.10.9;172.31.10.10;65000;64000;30;64030;10.69.1.0/24;3;10.69.1.1;10.69.2.0/24;2;10.69.2.1;10.69.3.0/24;1;10.69.3.1

10.30.0.2;ord;1031;172.31.10.12/30;172.31.10.13;172.31.10.14;65004;64004;40;64044;10.69.1.0/24;1;10.69.1.1;10.69.2.0/24;3;10.69.2.1;10.69.3.0/24;2;10.69.3.1
10.30.0.3;ord;1031;172.31.10.16/30;172.31.10.17;172.31.10.18;65004;64004;50;64054;10.69.1.0/24;2;10.69.1.1;10.69.2.0/24;1;10.69.2.1;10.69.3.0/24;3;10.69.3.1
10.30.0.4;ord;1031;172.31.10.20/30;172.31.10.21;172.31.10.22;65004;64004;60;64064;10.69.1.0/24;3;10.69.1.1;10.69.2.0/24;2;10.69.2.1;10.69.3.0/24;1;10.69.3.1

10.40.0.2;den;1041;172.31.10.24/30;172.31.10.25;172.31.10.26;65008;64008;70;64078;10.69.1.0/24;1;10.69.1.1;10.69.2.0/24;3;10.69.2.1;10.69.3.0/24;2;10.69.3.1
10.40.0.3;den;1041;172.31.10.28/30;172.31.10.29;172.31.10.30;65008;64008;80;64088;10.69.1.0/24;2;10.69.1.1;10.69.2.0/24;1;10.69.2.1;10.69.3.0/24;3;10.69.3.1
10.40.0.4;den;1041;172.31.10.32/30;172.31.10.33;172.31.10.34;65008;64008;90;64098;10.69.1.0/24;3;10.69.1.1;10.69.2.0/24;2;10.69.2.1;10.69.3.0/24;1;10.69.3.1";

my @fields;
my %h;
my %srx;
$srx{'stl1'} = "\n";
$srx{'ord1'} = "\n";
$srx{'den1'} = "\n";

my %siteint;
foreach my $s ( @{$c->{'bgp'}{'servers'}} ) {
	
	my $groupname = "site-srv-" . $s->{'ASN'};
	$groupname =~ s/\30//g;
	$groupname =~ s/\./-/g;
#	my $s = $s->{'site'};
	my $vlan = $s->{'vlan'};
    my $_net = new NetAddr::IP->new( $s->{'net'} );
	my $prefix = $_net->masklen();
	my $BGP_LOCAL = $_net->first()->addr();
	my $BGP_NEIGHBOR = $_net->last()->addr();

	my $ASN				 = 0;
	my $ASN_NEIGHBOR	 = 0;
	if ( defined ($c->{'bgp'}{'asn'}{'base'} ) ) 
	{
		$base = $c->{'bgp'}{'asn'}{'base'};
		my @bl = split ( /\./, $BGP_LOCAL );
		my @bn = split ( /\./, $BGP_NEIGHBOR );
		$ASN			 = $base + pop(@bl);
		$ASN_NEIGHBOR	 = $base + pop(@bn);

	} else {
		$ASN				 = $s->{'ASN'};
		$ASN_NEIGHBOR	 = $s->{'ASN_NEIGHBOR'};
	}
	

	if ( !defined ( $siteint{$s->{'site'}} ) ) {
		$srx{$s->{'site'}} .=	"delete interfaces ge-0/0/2 unit $vlan\n";
		$siteint{$s->{'site'}} = 1;
	}
	$srx{$s->{'site'}} .=	"set interfaces ge-0/0/2 unit $vlan family inet address ${BGP_NEIGHBOR}/$prefix\n";
	$srx{$s->{'site'}} .=	"set interfaces ge-0/0/2 unit $vlan vlan-id $vlan\n";
	$srx{$s->{'site'}} .= "delete protocols bgp group $groupname\n";
	$srx{$s->{'site'}} .= "set protocols bgp group $groupname type external\n";
	$srx{$s->{'site'}} .= "set protocols bgp group $groupname hold-time 20\n";
	$srx{$s->{'site'}} .= "set protocols bgp group $groupname advertise-peer-as\n";
	$srx{$s->{'site'}} .= "set protocols bgp group $groupname import import-service\n";
	$srx{$s->{'site'}} .= "set protocols bgp group $groupname export send-service\n";
	$srx{$s->{'site'}} .= "set protocols bgp group $groupname peer-as $ASN\n";
	$srx{$s->{'site'}} .= "set protocols bgp group $groupname as-override\n";
	$srx{$s->{'site'}} .= "set protocols bgp group $groupname local-as ${ASN_NEIGHBOR} loops 4\n";	
	$srx{$s->{'site'}} .= "set protocols bgp group $groupname bfd-liveness-detection minimum-interval 200\n";
	$srx{$s->{'site'}} .= "set protocols bgp group $groupname bfd-liveness-detection multiplier 6\n";
	$srx{$s->{'site'}} .= "set protocols bgp group $groupname multipath\n";
	$srx{$s->{'site'}} .= "set protocols bgp group $groupname neighbor ${BGP_LOCAL}\n";


my $SRVNET1	 = "";
my $SRVMED1	 = 0;
my $SRVIP1	 = "";
my $SRVNET2	 = "";
my $SRVMED2	 = 0;
my $SRVIP2	 = "";
my $SRVNET3	 = "";
my $SRVMED3	 = 0;
my $SRVIP3	 = "";

open FH, ">rc.conf.local-" . $s->{'name'} . "-" . $s->{'site'};
print FH "ifconfig_vtnet1=\"inet ${BGP_LOCAL}/$prefix up\"\n";
	
	foreach my $srvip ( @{$s->{'vips'}} ) {
		
		my $med = $srvip->{'med'};
		my $sx = new NetAddr::IP->new($srvip->{'vip'});
		if ( $med == 1 ) {
			$SRVNET1	 = $sx->network;
			$SRVMED1	 = 1;
			$SRVIP1	 = $sx->addr;
		}
		if ( $med == 2 ) {
			$SRVNET2	 = $sx->network;
			$SRVMED2	 = 2;
			$SRVIP2	 = $sx->addr;
		}
		if ( $med == 3 ) {
			$SRVNET3	 = $sx->network;
			$SRVMED3	 = 3;
			$SRVIP3	 = $sx->addr;
		}
		my $alias = $med - 1;
		print FH "ifconfig_lo0_alias${alias}=\"inet "  . $sx->cidr . "\"\n"; 

	}

close FH;

	my $bgpPath1 = "";
	my $bgpPath2 = "";
	my $bgpPath3 = "";
	for ( my $i=0; $i<$SRVMED1; $i++) { $bgpPath1 .= "			bgp_path.prepend(${ASN});\n"; }
	for ( my $i=0; $i<$SRVMED2; $i++) { $bgpPath2 .= "			bgp_path.prepend(${ASN});\n"; }
	for ( my $i=0; $i<$SRVMED3; $i++) { $bgpPath3 .= "			bgp_path.prepend(${ASN});\n"; }

open FH, ">bird-srv-mesh-" . $s->{'name'} . "-" . $s->{'site'} .  ".conf";
print FH <<EOF;
router id ${BGP_LOCAL};
#log stderr info;
debug protocols all;
debug commands 2;
protocol direct { }
protocol static { }

protocol bfd {
        debug { events, states };
        interface "vtnet*" {
            interval 150 ms;
            idle tx interval 300 ms;
            multiplier 6;
        };
}

protocol kernel {
	persist;		# Don't remove routes on bird shutdown;
	scan time 20;		# Scan kernel routing table every 20 seconds
	export all;		# Default is export none
#	kernel table 5;		# Kernel table to synchronize with (default: main)
#	import none;		# Default is import all
#	learn;			# Learn all alien routes from the kernel
}

protocol device { scan time 10;	 }

filter rfc192 {
	if ( net ~ 172.31.10.0/24 ) then {
		accept;
	}
	if ( net ~ 10.69.0.0/22 ) then {
		accept;
	}
	reject;
}

filter rfc192Export {
	if ( net ~ ${SRVNET1} ) then {
		if source = RTS_DEVICE then
		{
${bgpPath1}
			bgp_med = ${SRVMED1};
			accept;
		}
	}
	if ( net ~ ${SRVNET2} ) then {
		if source = RTS_DEVICE then
		{
${bgpPath2}
			bgp_med = ${SRVMED2};
			accept;
		}
	}
	if ( net ~ ${SRVNET3} ) then {
		if source = RTS_DEVICE then
		{
${bgpPath3}
			bgp_med = ${SRVMED3};
			accept;
		}
	}
	reject;
}


protocol bgp service1 {
	local as ${ASN};
	neighbor ${BGP_NEIGHBOR} as ${ASN_NEIGHBOR};
	direct;
	export filter rfc192Export;
	import filter rfc192;
	source address ${BGP_LOCAL};
	add paths on;
	med metric on;
	next hop self;
	allow local as 4;
    bfd;
    hold time 20;
}
EOF


close FH;
}
#open FH, ">/etc/rc.conf.d/bird";
#print FH "bird_enable=\"YES\"";
#close FH;
foreach my $site ( keys %srx ) 
{
	open FH, ">${site}" . "-mesh" . ".set";
	print FH $srx{$site};
	close FH;
}


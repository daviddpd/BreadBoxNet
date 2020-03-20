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

my @fields;
my %h;
my %srx;
$srx{'stl1'} = "\n";
$srx{'ord1'} = "\n";
$srx{'den1'} = "\n";

my @vipnets;

foreach my $v ( @{$c->{'bgp'}{'vips'}} ) {
	push @vipnets, new NetAddr::IP->new( $v->{'net'});
}


my %siteint;
foreach my $s ( @{$c->{'bgp'}{'servers'}} ) {
	
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
		my $base = $c->{'bgp'}{'asn'}{'base'};
		my @bl = split ( /\./, $BGP_LOCAL );
		my @bn = split ( /\./, $BGP_NEIGHBOR );
		$ASN			 = $base + pop(@bl);
		$ASN_NEIGHBOR	 = $base + pop(@bn);

	} else {
		$ASN				 = $s->{'ASN'};
		$ASN_NEIGHBOR	 = $s->{'ASN_NEIGHBOR'};
	}
	
	my $groupname = "srv-" . $s->{'site'} . "-" . $s->{'name'};

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
my $SRVNET;

open FH, ">rc.conf.local-" . $s->{'name'} . "-" . $s->{'site'};
print FH "ifconfig_vtnet1=\"inet ${BGP_LOCAL}/$prefix up\"\n";
	
	foreach my $srvip ( @{$s->{'vips'}} ) {
		
		my $med = $srvip->{'med'};
		my $sx = new NetAddr::IP->new($srvip->{'vip'});
		foreach my $vn ( @vipnets ) 
		{
			my $b = $vn->contains($sx);
			if ( $b ) {
				$SRVNET = $vn->network;
			}
			
			#printf ( " %d %s %s \n", $b, $vn, $sx );
		}
		
		if ( $med == 1 ) {
			$SRVNET1	 = $SRVNET;
			$SRVMED1	 = 1;
			$SRVIP1	 = $sx->addr;
		}
		if ( $med == 2 ) {
			$SRVNET2	 = $SRVNET;
			$SRVMED2	 = 2;
			$SRVIP2	 = $sx->addr;
		}
		if ( $med == 3 ) {
			$SRVNET3	 = $SRVNET;
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


protocol bgp srv1 {
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


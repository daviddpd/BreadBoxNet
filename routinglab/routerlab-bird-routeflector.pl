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
# 	foreach my $t ( @{$config->{'bgp'}} )
# 	{
# 	
# 		my $site1 = $t->{'site1'}->{'name'};
# 		my $site2 = $t->{'site2'}->{'name'};
# 
# 		 my $tunnel = {
# 				'psk' => $t->{'SharedSecret'},
# 				'sites' => [ $t->{'site1'}->{'name'},  $t->{'site2'}->{'name'} ],
# 				'ips' => {
# 					'bgpfullmesh' => {
# 						$site1 => $t->{'site1'}->{'bgpfullmesh'} || 0,
# 						$site2 => $t->{'site2'}->{'bgpfullmesh'} || 0,
# 					},
# 					'extint' => {
# 						$site1 => $t->{'site1'}->{'extint'},
# 						$site2 => $t->{'site2'}->{'extint'},
# 					},
# 					'localas' => {
# 						$site1 => $t->{'site1'}->{'localas'},
# 						$site2 => $t->{'site2'}->{'localas'},
# 					},
# 					'outer' => {
# 						$site1 => $t->{'site1'}->{'publicIP'},
# 						$site2 => $t->{'site2'}->{'publicIP'},
# 					},
# 					'inner' => {
# 						$site1 => $t->{'site1'}->{'privateIP'},
# 						$site2 => $t->{'site2'}->{'privateIP'},
# 					},
# 				},
# 			};
# 		 push @tunnels, $tunnel;
# 
# 	}
# 		return @tunnels;

}

my $c = parseIpFile_yaml($opt->ipfile);

my %srx;
#$srx{'stl'} = "\n";
#$srx{'ord'} = "\n";
#$srx{'den'} = "\n";
my %siteint;
my $myip = '';
foreach my $r ( @{$c->{'bgp'}{'router'}} ) {

	my $s = $r->{'site'};
	my $vlan = $r->{'vlan'};

    my $bl = new NetAddr::IP->new($r->{'BGP_LOCAL'});
    my $BGP_LOCAL = $bl->addr;
    my $BGP_LOCAL_CDIR = $bl->cidr;
    my $ASN = $r->{'ASN'};
    my $ASN_NEIGHBOR = $r->{'ASN_NEIGHBOR'};
    my $bn = new NetAddr::IP->new($r->{'BGP_NEIGHBOR'});
    my $BGP_NEIGHBOR = $bn->addr;
    my $BGP_NEIGHBOR_CDIR = $bn->cidr;
    
    my $net = new NetAddr::IP->new($r->{'net'});

    
    my $groupname = $r->{'name'} . "-" . $net->network;
    $groupname =~s/[\.\/]/-/g;	
		
	if ( !defined ( $siteint{$s} ) ) {
		$srx{$s} .=	"delete interfaces ge-0/0/2 unit $vlan\n";
		$siteint{$s} = 1;
		$srx{$s} .= "delete policy-options policy-statement send-service\n";
		$srx{$s} .= "delete policy-options policy-statement import-service\n";
		$srx{$s} .= "set policy-options policy-statement send-service term 1 then reject\n";
		$srx{$s} .= "set policy-options policy-statement import-service term 1 from route-filter 10.69.0.0/19 orlonger\n";
		$srx{$s} .= "set policy-options policy-statement import-service term 1 then accept\n";		
	}
	$srx{$s} .=	"set interfaces ge-0/0/2 unit $vlan family inet address ${BGP_LOCAL_CDIR}\n";
	$srx{$s} .=	"set interfaces ge-0/0/2 unit $vlan vlan-id $vlan\n";
	$srx{$s} .= "delete protocols bgp group $groupname\n";
	$srx{$s} .= "set protocols bgp group $groupname type external\n";
#	$srx{$s} .= "set protocols bgp group $groupname type internal\n";
	$srx{$s} .= "set protocols bgp group $groupname hold-time 20\n";
	$srx{$s} .= "set protocols bgp group $groupname advertise-peer-as\n";
	$srx{$s} .= "set protocols bgp group $groupname import import-service\n";
	$srx{$s} .= "set protocols bgp group $groupname export send-service\n";
	$srx{$s} .= "set protocols bgp group $groupname peer-as $ASN_NEIGHBOR\n";
	$srx{$s} .= "set protocols bgp group $groupname as-override\n";
	$srx{$s} .= "set protocols bgp group $groupname local-as $ASN loops 4 \n";
	
	$srx{$s} .= "set protocols bgp group $groupname bfd-liveness-detection minimum-interval 200\n";
	$srx{$s} .= "set protocols bgp group $groupname bfd-liveness-detection multiplier 6\n";
	$srx{$s} .= "set protocols bgp group $groupname multipath\n";
	$srx{$s} .= "set protocols bgp group $groupname neighbor $BGP_NEIGHBOR\n";
	
}

# print Dumper ( %srx );

foreach my $site ( keys %srx ) 
{
	open FH, ">${site}-rr.set";
	print FH $srx{$site};
	close FH;
}


foreach my $r ( @{$c->{'bgp'}{'routerservers'}} ) {

    my $bl = new NetAddr::IP->new($r->{'BGP_LOCAL'});
    my $BGP_LOCAL = $bl->addr;
    my $BGP_LOCAL_CDIR = $bl->cidr;
    my $ASN = $r->{'ASN'};
    
    my $bn = new NetAddr::IP->new($r->{'BGP_NEIGHBOR'});
    my $BGP_NEIGHBOR = $bn->addr;
    my $BGP_NEIGHBOR_CDIR = $bn->cidr; 
	my $NET = $r->{'net'};
	my $prefix = $bn->masklen();
	
 	my $ASN_NEIGHBOR	 = $r->{'ASN_NEIGHBOR'};
 	my $VIPNET = $r->{'vipnet'};
# 	my $SRVNET1	 = $h{$ip}{'SRVNET1'};
# 	my $SRVMED1	 = $h{$ip}{'SRVMED1'};
# 	my $SRVIP1	 = $h{$ip}{'SRVIP1'};
# 	my $SRVNET2	 = $h{$ip}{'SRVNET2'};
# 	my $SRVMED2	 = $h{$ip}{'SRVMED2'};
# 	my $SRVIP2	 = $h{$ip}{'SRVIP2'};
# 	my $SRVNET3	 = $h{$ip}{'SRVNET3'};
# 	my $SRVMED3	 = $h{$ip}{'SRVMED3'};
# 	my $SRVIP3	 = $h{$ip}{'SRVIP3'};
#	my @octets =  split ( /\./, $s->{'ip'} );
#	my $ASN = $s->{'ASNBASE'} + scalar ($octets[3]);


my $neighbor="";
foreach my $s ( @{$c->{'bgp'}{'servers'}} ) {
	my $BGP_NEIGHBOR = $s->{'ip'};
	my $ASN_NEIGHBOR = $s->{'ASN'};
	
	my $name = $s->{'name'};
	$name =~ s/\.//g;

	my $BGP_LOCAL = $r->{'ip'};
	my $ASN = $r->{'ASN'};
	
	
	$neighbor .= "
protocol bgp rs2srv${name} {
	local as ${ASN};
	neighbor ${BGP_NEIGHBOR} as ${ASN_NEIGHBOR};
	direct;
	import filter vipnets;
	export filter rejectFilter;
	source address ${BGP_LOCAL};
	rs client;
	add paths on;
	med metric on;
	next hop keep;
	allow local as 6;
	bfd;
	hold time 20;
}
";


}

open FH, ">bird-RR-" . $r->{'name'} . "-" . $r->{'site'} .  ".conf";
print FH<<EOF;

######### BGP HA Route Reflector  #############

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

filter vipnets {
	if ( net ~ ${VIPNET} ) then {
		accept;
	}
	reject;
}

filter rejectFilter {
	reject;
}

protocol bgp up2srx {
	local as ${ASN};
	neighbor ${BGP_NEIGHBOR} as ${ASN_NEIGHBOR};
	direct;
	export filter vipnets;
	import filter rejectFilter;
	source address ${BGP_LOCAL};
	add paths on;
	med metric on;
	next hop keep;
	allow local as 6;
	bfd;
	hold time 20;
}



$neighbor


EOF
close FH;







# 
# open FH, ">/etc/rc.conf.d/bird";
# print FH "bird_enable=\"YES\"";
# close FH;

# my $bgpPath1 = "";
# my $bgpPath2 = "";
# my $bgpPath3 = "";
# for ( my $i=0; $i<$SRVMED1; $i++) { $bgpPath1 .= "bgp_path.prepend(${ASN});\n"; }
# for ( my $i=0; $i<$SRVMED2; $i++) { $bgpPath2 .= "bgp_path.prepend(${ASN});\n"; }
# for ( my $i=0; $i<$SRVMED3; $i++) { $bgpPath3 .= "bgp_path.prepend(${ASN});\n"; }
# 
# #open FH, ">/usr/local/etc/bird.conf";
}



my $VIPNET = '';

foreach my $s ( @{$c->{'bgp'}{'servers'}} ) {
	my $rr = "";
	my $BGP_LOCAL = $s->{'ip'};
	my $ASN = $s->{'ASN'};

	my $filterNets = '';
	foreach my $vip ( @{$s->{'vips'}} ) {

		print Dumper ( $vip );
	    my $SRV = new NetAddr::IP->new($vip->{'vip'});
	    my $SRVNET = $SRV->network;
	    my $SRVMED = $vip->{'med'};
		my $bgpPath1 = "";
		for ( my $i=0; $i<$vip->{'med'}; $i++) { $bgpPath1 .= "			bgp_path.prepend(${ASN});\n"; }

		$filterNets .= "
	if ( net ~ ${SRVNET} ) then {
		if source = RTS_DEVICE then
		{
${bgpPath1}
			bgp_med = ${SRVMED};
			accept;
		}
	}
";

	}

my $srvExport = "
filter srvExport {
$filterNets
	reject;
}
";	



foreach my $r ( @{$c->{'bgp'}{'routerservers'}} ) {

 	$VIPNET = $r->{'vipnet'};

	my $BGP_NEIGHBOR = $r->{'ip'};
	my @octets =  split ( /\./, $r->{'ip'} );	
	my $name = $s->{'name'} . "TO" . $r->{'name'};
	$name =~ s/\.//g;
	my $ASN = $s->{'ASN'};
	my $ASN_NEIGHBOR = $r->{'ASN_NEIGHBOR'};
	
	$rr .= "
protocol bgp $name {
	local as ${ASN};
	neighbor ${BGP_NEIGHBOR} as ${ASN_NEIGHBOR};
	direct;
	import filter rejectFilter;
	export filter srvExport;	
	source address ${BGP_LOCAL};
	add paths on;
	med metric on;
	next hop keep;
	allow local as 6;
	bfd;
	hold time 20;
}
";

}



	
	
open FH, ">bird-service-" . $s->{'name'} . "-" . $s->{'site'} .  ".conf";
print FH<<EOF;

######### BGP Service Route Injector #############

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

filter vipnets {
	if ( net ~ ${VIPNET} ) then {
		accept;
	}
	reject;
}

filter rejectFilter {
	reject;
}

$srvExport

$rr

EOF
close FH;


}


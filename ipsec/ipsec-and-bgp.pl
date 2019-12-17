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
	[ 'ipfile|f=s', "file with all the ips mappings", { required => 1 } ],	
	[ 'outdir|o=s', "Output Directory", { required => 1 } ],	
	
);

my $bgp ="

delete policy-options policy-statement import-bgp 
delete policy-options policy-statement send-direct

set security flow tcp-mss ipsec-vpn mss 1350

set policy-options as-path locallen \"64645{0,3}\"
set policy-options policy-statement send-direct term 3 from protocol direct
set policy-options policy-statement send-direct term 3 from route-filter 10.0.0.0/8 orlonger
set policy-options policy-statement send-direct term 3 from route-filter 192.168.0/16 orlonger
set policy-options policy-statement send-direct term 3 from route-filter 172.16.0.0/12 orlonger

set policy-options policy-statement send-direct term 3 then as-path-prepend 64645
set policy-options policy-statement send-direct term 3 then accept
set policy-options policy-statement send-direct term 2 from protocol bgp
set policy-options policy-statement send-direct term 2 from route-filter 10.0.0.0/8 orlonger
set policy-options policy-statement send-direct term 2 from route-filter 192.168.0/16 orlonger
set policy-options policy-statement send-direct term 2 from route-filter 172.16.0.0/12 orlonger

set policy-options policy-statement send-direct term 2 from as-path locallen
set policy-options policy-statement send-direct term 2 then as-path-prepend 64645
set policy-options policy-statement send-direct term 2 then next-hop self
set policy-options policy-statement send-direct term 2 then accept
set policy-options policy-statement send-direct term 1 from protocol ospf
set policy-options policy-statement send-direct term 1 from route-filter 10.0.0.0/8 orlonger
set policy-options policy-statement send-direct term 1 from route-filter 192.168.0/16 orlonger
set policy-options policy-statement send-direct term 1 from route-filter 172.16.0.0/12 orlonger

set policy-options policy-statement send-direct term 1 then as-path-prepend 64645
set policy-options policy-statement send-direct term 1 then accept

set policy-options policy-statement import-bgp term 1 from route-filter 10.0.0.0/8 orlonger
set policy-options policy-statement import-bgp term 1 from route-filter 192.168.0/16 orlonger
set policy-options policy-statement import-bgp term 1 from route-filter 172.16.0.0/12 orlonger
set policy-options policy-statement import-bgp term 1 from as-path locallen
set policy-options policy-statement import-bgp term 1 then accept

delete policy-options policy-statement ospf-import-bgp 
set policy-options policy-statement ospf-import-bgp term 1 from protocol bgp
set policy-options policy-statement ospf-import-bgp term 1 then next-hop self
set policy-options policy-statement ospf-import-bgp term 1 then accept
set protocols ospf export ospf-import-bgp

delete protocols bgp group intra-srx
set protocols bgp group intra-srx type internal
set protocols bgp group intra-srx advertise-peer-as
set protocols bgp group intra-srx family inet unicast add-path receive
set protocols bgp group intra-srx family inet unicast add-path send path-count 6
set protocols bgp group intra-srx export send-direct
set protocols bgp group intra-srx import import-bgp
set protocols bgp group intra-srx cluster 0.0.0.0  # Advanced BGP licence (SRX-BGP-ADV-LTU) is need for SRX650
set protocols bgp group intra-srx local-as 64645
set protocols bgp group intra-srx local-as loops 2
set protocols bgp group intra-srx multipath
set protocols bgp group intra-srx hold-time 20
set protocols bgp group intra-srx bfd-liveness-detection minimum-interval 200
set protocols bgp group intra-srx bfd-liveness-detection multiplier 6

";

my $racoonconf = "
remote anonymous
{
	exchange_mode aggressive,main,base;
	lifetime time 24 hour;
	proposal {
		encryption_algorithm aes;
		hash_algorithm sha1;
		authentication_method pre_shared_key;
		dh_group 2;
	}
}

sainfo anonymous
{
	pfs_group 2;
	lifetime time 86400 seconds;
	encryption_algorithm aes;
	authentication_algorithm hmac_sha256;
	compression_algorithm deflate;
}

path pre_shared_key \"/usr/local/etc/racoon/psk.txt\";

";



sub readFile {
	my $filename = shift;
	my $buffer;
	my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($filename);
	open FHX, "<$filename";
	read (FHX,$buffer,$size);
	close FHX;
	return $buffer;
}

sub parseIpFile {
	my $filename = shift;
	my $buffer;
	my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat($filename);
	open FHX, "<$filename";
	read (FHX,$buffer,$size);
	close FHX;

	my @tunnels;
	foreach my $l (split ("\n", $buffer) ) {

		chomp($l);
		if ( $l =~ m/^#/ ) { next; }
		my ($o,$i,$s,$o2,$i2,$s2,$psk) = split ('[\t\s]+', $l);
	
		if ( $psk =~ /^\$(GEN|GENERATE|RAN|RANDOM)/ ) {
			$psk = pskGen(1024,64);
		}

		 push @tunnels, {
				'psk' => $psk,
				'sites' => [$s,$s2],
				'ips' => {
					'outer' => { 
						$s => $o,
						$s2 => $o2,
					},
					'inner' => {
						$s => $i,
						$s2 => $i2,
					},
				},
			};
	}
	
	return @tunnels;
}


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

sub ipsecGen {
    my $tunnel = shift;
    my $flip = shift;
    my $SHARED_KEY = $tunnel->{'psk'};

    my @sites_sorted = sort @{$tunnel->{'sites'}};
    my $site1 = $sites_sorted[0];
    my $site2 = $sites_sorted[1];
    if ( $flip ) {
        $site1 = $sites_sorted[1];
        $site2 = $sites_sorted[0];
    }
    my $NAME = "${site1}-2-${site2}";
    my $EXT_INT  = "ge-0/0/0";

    my $DEST_IP = $tunnel->{'ips'}->{'outer'}->{$site2};
    my $DEST_IP_OUTER = $DEST_IP;
    my $SRC_IP_OUTER = $tunnel->{'ips'}->{'outer'}->{$site1};
    my $ipsrcouter = new NetAddr::IP->new($SRC_IP_OUTER);
    my $SRC_IP = $ipsrcouter->addr();
        
    my $DEST_IP_INNER_CIDR = $tunnel->{'ips'}->{'inner'}->{$site2};
    my $LOCAL_IP_INNER_CIDR = $tunnel->{'ips'}->{'inner'}->{$site1}; 
    my $TUN_ADDR = $LOCAL_IP_INNER_CIDR;

    my $ip_outdst = new NetAddr::IP->new($DEST_IP);
    $DEST_IP = $ip_outdst->addr();

    my $ipdstinner = new NetAddr::IP->new($DEST_IP_INNER_CIDR);
    my $DEST_IP_INNER = $ipdstinner->addr;
    my $INNER_CIDR = $ipdstinner->network;
    my $ipsrcinner = new NetAddr::IP->new($LOCAL_IP_INNER_CIDR);
    my $LOCAL_IP_INNER = $ipsrcinner->addr;
    my $INNER_TUNNEL_MASK =  $ipsrcinner->mask();

	my $SITE = $site2;
	
	
	
	

# Systematically create the tunnel unit as the value of the last octet
# of the network address.
#
    my $net =$ipdstinner->network();
    my @a = split (/[\.\/]/, $net );
    my $TUN = "st0";
    my $TUN_UNIT = $a[3];
    my $TUN_INT = "${TUN}.${TUN_UNIT}";
   
    my %config;



        
        $config{'meta'}{'to'} = $site2;
        $config{'meta'}{'from'} = $site1;

my $bird_bgp ="
protocol bgp ${SITE} {
	local as 64645;
	neighbor ${DEST_IP_INNER} as 64645;
	direct;
	export filter rfc192Export;
	import filter rfc192;
	source address ${LOCAL_IP_INNER};
	rr cluster id  0.0.0.0;
	rr client;
	add paths on;
	med metric on;
	next hop self;
	allow local as 4;
    bfd;
    hold time 20;
}
";


        push @{$config{'freebsd'}{'bird'}{'bgp'}}, $bird_bgp;
        push @{$config{'freebsd'}{'rc'}{'ifconfig'}},  "ifconfig_ipsec${TUN_UNIT}=\"inet ${LOCAL_IP_INNER} ${DEST_IP_INNER} netmask ${INNER_TUNNEL_MASK} tunnel ${SRC_IP} ${DEST_IP} reqid ${TUN_UNIT} mtu 1350\"";
        push @{$config{'freebsd'}{'rc'}{'cloned_interfaces'}}, "ipsec${TUN_UNIT}";
        push @{$config{'freebsd'}{'racoon'}{'setkey'}}, "spdadd -4n ${INNER_CIDR} ${INNER_CIDR} any -P out ipsec esp/tunnel/${SRC_IP}-${DEST_IP}/unique:${TUN_UNIT};";
        push @{$config{'freebsd'}{'racoon'}{'setkey'}}, "spdadd -4n ${INNER_CIDR} ${INNER_CIDR} any -P in  ipsec esp/tunnel/${DEST_IP}-${SRC_IP}/unique:${TUN_UNIT};";
        push @{$config{'freebsd'}{'racoon'}{'psk'}}, "${DEST_IP}	${SHARED_KEY}";

        push @{$config{'freebsd'}{'racoon'}{'conf'}}, "remote ${DEST_IP} [500] {";
        push @{$config{'freebsd'}{'racoon'}{'conf'}}, "	passive off;";
        push @{$config{'freebsd'}{'racoon'}{'conf'}}, "	my_identifier address ${LOCAL_IP_INNER};";
        push @{$config{'freebsd'}{'racoon'}{'conf'}}, "	exchange_mode main;";
        push @{$config{'freebsd'}{'racoon'}{'conf'}}, "	lifetime time 24 hour;";
        push @{$config{'freebsd'}{'racoon'}{'conf'}}, "	proposal {";
        push @{$config{'freebsd'}{'racoon'}{'conf'}}, "		encryption_algorithm aes;";
        push @{$config{'freebsd'}{'racoon'}{'conf'}}, "		hash_algorithm sha1;";
        push @{$config{'freebsd'}{'racoon'}{'conf'}}, "		authentication_method pre_shared_key;";
        push @{$config{'freebsd'}{'racoon'}{'conf'}}, "		dh_group 2; }}";


        push @{$config{'junos'}{'ike'}{'proposal'}},  "delete security ike proposal ike-prop-${NAME}";
        push @{$config{'junos'}{'ike'}{'proposal'}},  "set security ike proposal ike-prop-${NAME} authentication-method pre-shared-keys";
        push @{$config{'junos'}{'ike'}{'proposal'}},  "set security ike proposal ike-prop-${NAME} authentication-algorithm sha1";
        push @{$config{'junos'}{'ike'}{'proposal'}},  "set security ike proposal ike-prop-${NAME} encryption-algorithm aes-128-cbc";

        push @{$config{'junos'}{'ike'}{'policy'}},  "delete security ike policy ike-policy-${NAME}";
        push @{$config{'junos'}{'ike'}{'policy'}},  "set security ike policy ike-policy-${NAME} mode main";
        push @{$config{'junos'}{'ike'}{'policy'}},  "set security ike policy ike-policy-${NAME} proposals ike-prop-${NAME}";
        push @{$config{'junos'}{'ike'}{'policy'}},  "set security ike policy ike-policy-${NAME} pre-shared-key ascii-text \"${SHARED_KEY}\"";

        push @{$config{'junos'}{'ike'}{'gateway'}},  "delete security ike gateway ike-gate-${NAME}";
        push @{$config{'junos'}{'ike'}{'gateway'}},  "set security ike gateway ike-gate-${NAME} ike-policy ike-policy-${NAME}";
        push @{$config{'junos'}{'ike'}{'gateway'}},  "set security ike gateway ike-gate-${NAME} address ${DEST_IP}";
        push @{$config{'junos'}{'ike'}{'gateway'}},  "set security ike gateway ike-gate-${NAME} dead-peer-detection interval 10";
        push @{$config{'junos'}{'ike'}{'gateway'}},  "set security ike gateway ike-gate-${NAME} dead-peer-detection threshold 5";
        push @{$config{'junos'}{'ike'}{'gateway'}},  "set security ike gateway ike-gate-${NAME} local-identity inet ${SRC_IP}";
        push @{$config{'junos'}{'ike'}{'gateway'}},  "set security ike gateway ike-gate-${NAME} remote-identity inet ${DEST_IP}";
        push @{$config{'junos'}{'ike'}{'gateway'}},  "set security ike gateway ike-gate-${NAME} external-interface ${EXT_INT}";

#        push @{$config{'junos'}{'ipsec'}{'vpn-monitor-options'}},  "set security ipsec vpn-monitor-options interval 10";
#       push @{$config{'junos'}{'ipsec'}{'vpn-monitor-options'}},  "set security ipsec vpn-monitor-options threshold 5";

        push @{$config{'junos'}{'ipsec'}{'proposal'}},  "delete security ipsec proposal ipsec-prop-${NAME}";
        push @{$config{'junos'}{'ipsec'}{'proposal'}},  "set security ipsec proposal ipsec-prop-${NAME} protocol esp";
        push @{$config{'junos'}{'ipsec'}{'proposal'}},  "set security ipsec proposal ipsec-prop-${NAME} authentication-algorithm hmac-sha-256-128";
        push @{$config{'junos'}{'ipsec'}{'proposal'}},  "set security ipsec proposal ipsec-prop-${NAME} encryption-algorithm aes-128-cbc";
        push @{$config{'junos'}{'ipsec'}{'proposal'}},  "set security ipsec proposal ipsec-prop-${NAME} lifetime-seconds 86400";

        push @{$config{'junos'}{'ipsec'}{'policy'}},  "delete security ipsec policy ipsec-policy-${NAME} ";
        push @{$config{'junos'}{'ipsec'}{'policy'}},  "set security ipsec policy ipsec-policy-${NAME} perfect-forward-secrecy keys group2";
        push @{$config{'junos'}{'ipsec'}{'policy'}},  "set security ipsec policy ipsec-policy-${NAME} proposals ipsec-prop-${NAME}";

        push @{$config{'junos'}{'ipsec'}{'vpn'}},  "delete security ipsec vpn ipsec-vpn-${NAME}";
        push @{$config{'junos'}{'ipsec'}{'vpn'}},  "set security ipsec vpn ipsec-vpn-${NAME} bind-interface ${TUN_INT}";
        push @{$config{'junos'}{'ipsec'}{'vpn'}},  "set security ipsec vpn ipsec-vpn-${NAME} vpn-monitor optimized";
        push @{$config{'junos'}{'ipsec'}{'vpn'}},  "set security ipsec vpn ipsec-vpn-${NAME} ike gateway ike-gate-${NAME}";
        push @{$config{'junos'}{'ipsec'}{'vpn'}},  "set security ipsec vpn ipsec-vpn-${NAME} ike ipsec-policy ipsec-policy-${NAME}";
        push @{$config{'junos'}{'ipsec'}{'vpn'}},  "set security ipsec vpn ipsec-vpn-${NAME} establish-tunnels immediately";

        push @{$config{'junos'}{'interfaces'}{'unit'}},  "delete interfaces ${TUN} unit ${TUN_UNIT}";
        push @{$config{'junos'}{'interfaces'}{'unit'}},  "set interfaces ${TUN} unit ${TUN_UNIT} description \"$NAME\"";
        push @{$config{'junos'}{'interfaces'}{'unit'}},  "set interfaces ${TUN} unit ${TUN_UNIT} family inet address ${TUN_ADDR}";

        push @{$config{'junos'}{'zones'}{'trust'}},  "delete security zones security-zone trust interfaces ${TUN}.${TUN_UNIT} ";
        push @{$config{'junos'}{'zones'}{'trust'}},  "set security zones security-zone trust interfaces ${TUN}.${TUN_UNIT} host-inbound-traffic system-services all";
        push @{$config{'junos'}{'zones'}{'trust'}},  "set security zones security-zone trust interfaces ${TUN}.${TUN_UNIT} host-inbound-traffic protocols all";
        
        
        push @{$config{'junos'}{'protocols'}{'bgp'}},  "set protocols bgp group intra-srx neighbor ${DEST_IP_INNER}";
        

	return %config;
}






print($usage->text), exit if $opt->help;

my @tunnels = parseIpFile($opt->{'ipfile'});
my %configs;
my %freebsd;
foreach my $tunnel ( @tunnels ) {
#    my $psk = pskGen(1024,64);
    foreach my $flip ( ( 0,1 ) ) {
        my %tun0 = ipsecGen ( $tunnel, $flip);
        my %tun = %{$tun0{'junos'}};
        my $site = $tun0{'meta'}{'from'};
        my $site_to = $tun0{'meta'}{'to'};
        print " ==> $site to $site_to \n";
#        if ( !defined ($configs{$site}) ) {
#            $configs{$site} = "";
#        }
        foreach my $section ( sort keys %tun ) 
        {
            next if ( $section =~ /meta/ );
            foreach my $block ( sort keys %{$tun{$section}} ) {
                foreach my $line ( @{$tun{$section}{$block}} ) {
                    printf ( " %5s %s\n", $site, $line );
                    $configs{$site} .= $line . "\n";
                }
            }
        }
        %tun = %{$tun0{'freebsd'}};        
        foreach my $section ( sort keys %tun ) 
        {
            next if ( $section =~ /meta/ );
	            foreach my $block ( sort keys %{$tun{$section}} ) {
	                foreach my $line ( @{$tun{$section}{$block}} ) {
		            	if ( $block =~ /ifconfig/ ) {
		                    $freebsd{$site}{'rc.conf'} .= $line . "\n";
	        	    	} elsif  ( $block =~ /cloned_interfaces/ ) {
		        	    	$freebsd{$site}{'cloned_interfaces'} .= " " . $line;
	        	    	} elsif  ( ($block =~ /conf/) && ($section =~/racoon/) ) {
		        	    	$freebsd{$site}{"$section.$block"} .=  $line . "\n";
	        	    	} elsif  ( ($block =~ /bgp/) && ($section =~/bird/) ) {
		        	    	$freebsd{$site}{"$section.$block"} .=  $line . "\n";
	        	    	} else {
		        	    	$freebsd{$site}{$block} .=  $line . "\n";	    	
	        	    	}
	        	    }
	            }            
		}
    }
}



foreach my $site ( sort keys %configs ) 
{
	if ( ! -d $opt->{'outdir'} ) 
	{
		mkdir $opt->{'outdir'}
	}
    open FH,">" . $opt->{'outdir'} . "/$site.set";
	print FH $bgp;
    print FH $configs{$site};
    close FH;
    
	foreach my $block ( sort keys %{$freebsd{$site}} ) 
	{
		printf ( " ===> %s \n", $block );
		next if ( $block =~ /cloned_interfaces/ );
	    open FH,">" . $opt->{'outdir'} . "/$site-$block.txt";
		if ( $block =~ /rc.conf/ ) {
		    print FH "cloned_interfaces=\"" . $freebsd{$site}{'cloned_interfaces'} . "\"\n";
		} elsif ( $block =~ /setkey/ ) {
		    print FH "flush;\n";
		    print FH "spdflush;\n\n";
		} elsif ( $block =~ /racoon\.conf/ ) {	
		    print FH $racoonconf;
		} elsif ( $block =~ /bird\.bgp/ ) {	
			my $bird = readFile("bird.conf");
		    print FH $bird . "\n";
		} 
	    print FH $freebsd{$site}{$block} . "\n";
    }
}
# BreadBoxNet
Juniper, Arista, FreeBSD, IKE/IPSEC, Raccoon et al Configs and Scripts to Generate Configs.

## ipsec-and-bgp.pl

This generates configs of N-way IPSEC tunnels between (in theory any number of)
Juniper SRX's and FreeBSD IPSEC/Racoon systems.

```
> perl ipsec-and-bgp.pl
Mandatory parameter 'ipfile' missing in call to "eval"

ipsec-and-bgp.pl [-fhov] [long options...]
	-h --help            help, print usage
	-v --verbose         verbose
	-f STR --ipfile STR  file with all the ips mappings
	-o STR --outdir STR  Output Directory

```

The -f / --ipfile is the config as described below.
-o / --outdir is the output directory (multiple files are created).  Directory is created
if it doesn't exists.

## Create the config file.

From RFC 5737 using the IPv4 Address Blocks Reserved for Documentation as "public IPS"

 * 192.0.2.0/24 (TEST-NET-1)
 * 98.51.100.0/24 (TEST-NET-2)
 * 203.0.113.0/24 (TEST-NET-3)

And using RFC 1918 space for the Point-to-Point Layer3

| NET    | IP1 | IP2 |
| ----------- | ----------- | ----------- |
| 172.16.255.0/30	| 172.16.255.1 |	172.16.255.2 |
| 172.16.255.4/30 |	172.16.255.5 |	172.16.255.6 |
| 172.16.255.8/30 | 172.16.255.9 | 172.16.255.10 |
| 172.16.255.12/30 | 172.16.255.13 | 172.16.255.14 |


```
#Site1:PublicIP   Site1:PrivateIP    Site1:Name   Site2:PublicIP    Site2:PrivateIP    Site2:Name   SharedSecret
192.0.2.1/24      172.31.255.1/30    test1        98.51.100.1/24    172.31.255.2/30    test2        $GENERATE
192.0.2.1/24      172.31.255.9/30    test1        203.0.113.1/24    172.31.255.10/30   test3        $GENERATE
98.51.100.1/24    172.31.255.13/30   test2        203.0.113.1/24    172.31.255.14/30   test3        $GENERATE
```


## Issues

* ASN 64645 is hard coded
* Juniper EXT_INT is hard coded, needs to changed, especially when in chassis cluster. (ge -> reth)
* bird is still only filtering 10/8
* dh group 2 may be required for Raccoon compatibility  

### Juniper SRX IKE Debugging
* IKEv1 with status No proposal chosen
* No proposal chosen (14)
* IKEv1 Error : No proposal chosen
* IKEv2 SA select failed with error No proposal chosen

Typically this is caused by:
* pre-shared-key are mismatched
* `security ike gateway ike-gate-${NAME} (remote|local)-identity inet [...]`
	* the ips are wrong, previous iteration used the INNER IPs of the tunnels, but this should be the public (outer) IPs.
* `security ike gateway ike-gate-${NAME} external-interface ${EXT_INT}`
	* EXT_INT needs to be in security zone
	*
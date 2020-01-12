# BreadBoxNet : IPSEC
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
	-f STR --ipfile STR  file with all the ips mappings, flat text, auto detectes via extentation yaml files - .yml/.yaml
	-o STR --outdir STR  Output Directory

The -f / --ipfile is the config as described below.
-o / --outdir is the output directory (multiple files are created).  Directory is created
if it doesn't exists.
```

## Create the config file.

From RFC 5737 using the IPv4 Address Blocks Reserved for Documentation as "public IPS"

 * 192.0.2.0/24 (TEST-NET-1)
 * 98.51.100.0/24 (TEST-NET-2)
 * 203.0.113.0/24 (TEST-NET-3)

And using RFC 1918 space for the Point-to-Point Layer3

| NET | IP1| IP2|
| ----------- | ----------- | ----------- |
| 172.16.255.0/30	| 172.16.255.1 | 172.16.255.2 |
| 172.16.255.4/30 |	172.16.255.5 | 172.16.255.6 |
| 172.16.255.8/30 | 172.16.255.9 |  172.16.255.10 |
| 172.16.255.12/30 | 172.16.255.13 | 172.16.255.14 |


### Flat text config files
```
#Site1:PublicIP   Site1:PrivateIP    Site1:Name  Site1:extint  Site1:localas   Site2:PublicIP    Site2:PrivateIP    Site2:Name  Site1:extint  Site1:localas  SharedSecret
192.0.2.1/24      172.31.255.1/30    test1   ge-0/0/0       64645      98.51.100.1/24    172.31.255.2/30    test2   ge-0/0/1       64645      $GENERATE
192.0.2.1/24      172.31.255.9/30    test1   ge-0/0/1       64645      203.0.113.1/24    172.31.255.10/30   test3   ge-0/0/1       64645      $GENERATE
98.51.100.1/24    172.31.255.13/30   test2   ge-0/0/1       64645      203.0.113.1/24    172.31.255.14/30   test3   ge-0/0/1       64645      $GENERATE
```

### YAML File Format
```
---
ipsec:
    - tunnel: "Tunnel 1"
      site1:
        publicIP:
        privateIP:
        name:
        extint:
        localas:
      site2:
        publicIP:
        privateIP:
        name:
        extint:
        localas:
      SharedSecret:

    - tunnel: "Tunnel 2"
      site1:
        publicIP:
        privateIP:
        name:
        extint:
        localas:
      site2:
        publicIP:
        privateIP:
        name:
        extint:
        localas:
      SharedSecret:
```

## Issues

* Route reflector - cluster - requires Advanced BGP licence (SRX-BGP-ADV-LTU) for SRX650, so for the time being, this moved into comments (see ~ line 80)
* ~ASN 64645 is hard coded~
* ~Juniper EXT_INT is hard coded, needs to changed, especially when in chassis cluster. (ge -> reth)~
* Adding Site1:extint  Site1:localas to address this short comings.  Local AS is still not used, but has config space
* Added a YAML config file.  Future versions will likely drop flat text config file.
* bird is still only filtering 10/8
* dh group 2 may be required for Raccoon compatibility
* Latest changes have not been tested with the OpenSource side (FreeBSD, IKE/IPSEC, Raccoon)

### Juniper SRX IKE Debugging
* IKEv1 with status No proposal chosen
* No proposal chosen (14)
* IKEv1 Error : No proposal chosen
* IKEv2 SA select failed with error No proposal chosen
* Peer's IKE-ID validation failed during negotiation

Typically this is caused by:
* pre-shared-key are mismatched
* `security ike gateway ike-gate-${NAME} (remote|local)-identity inet [...]`
	* the ips are wrong, previous iteration used the INNER IPs of the tunnels, but this should be the public (outer) IPs.
* `security ike gateway ike-gate-${NAME} external-interface ${EXT_INT}`
	* EXT_INT needs to be in security zone
* character encoding translation issues - especially when copy/pasting over an SSH connection to a serial console.
  * Tip: `start shell` and use `cat > x.set`, then paste, then Cntrl-D to close file.  back to `cli`, `edit` and then `load set x.set`
	* When possible, compose in a decent text editor and SCP file to the SRX.
	* Tip: Configure over the serial console, the system, ssh and a management port, even a non-routed network.  Faster and nicer than 9600 bps. 
* Peer's IKE-ID validation failed during negotiation
  * The `my_identifier address` in raccon is mismatched to the `remote-identity` on the Juniper side.  Or the remote-identity/local-identity are mismatched between two Junipers. It is unclear if there is a specific string or IP these idenifiers should be, but it appears that they are just that - an identifier, not specified by the protocol. So, whether this is the InnerIP or the OuterIP - may not matter, as long as they are aligned.
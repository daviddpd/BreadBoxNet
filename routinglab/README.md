# BreadBoxNet

## Routing Lab BGP High Availability / HA of Services

 * routerlab-bird-routeflector.pl
   * attempt at a using a route reflector in bird, that feeds to the SRX.
   * Not working. Note: The srx650 does not have bgp route reflection 

 * routerlab-bird-mesh.pl
   * With a single router (or HA pair), each Service Node will connect via BGP to the SRX.
   * code needs cleanup.
   * (1)Note, eBGP is used here, as Juniper SRX will not redistribute chain iBGP routes over iBGP. 
     * this is probably where route reflection will be useful.

```   
     NX[123](bird) <-- eBGP(1) --> { SRX-SITE1 } <--- Internet ---> { SRX-SITE2 }  <-- eBGP(1) --> NX[123](bird)  
                                       \________ IPSEC w/ iBGP _________/
```

## The Routing Lab 

Juniper SRX

* stl = srx240
* den = srx650
* ord = srx650

FreeBSD bhyve VM Routers

* gw-dfw1
* gw-inet
* gw-sea1

FreeBSD bhyve VM Hosts

* nx1.den1
* nx1.ord1
* nx1.stl1
* nx2.den1
* nx2.ord1
* nx2.stl1
* nx3.den1
* nx3.ord1
* nx3.stl1

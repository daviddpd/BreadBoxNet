# Juniper SRX [1256]00's 

Higher end SRXs do pcap/tcdumps differently.

```
set firewall filter PCAP term 1 from source-address a.b.c.d/32
set firewall filter PCAP term 1 then sample
set firewall filter PCAP term 1 then accept
set firewall filter PCAP term 2 from source-address 0.0.0.0/0
set firewall filter PCAP term 2 from destination-address a.b.c.d/32
set firewall filter PCAP term 2 then sample
set firewall filter PCAP term 2 then accept
set firewall filter PCAP term 3 then accept

set forwarding-options packet-capture file filename srxiad1pcap
set forwarding-options packet-capture file files 5
set forwarding-options packet-capture file size 1m
set forwarding-options packet-capture maximum-capture-size 1500

set interfaces reth0 unit 302 family inet filter input PCAP
set interfaces reth0 unit 302 family inet filter output PCAP
```


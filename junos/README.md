# BreadBoxNet : JunOS Tips
***

## SRX
### Cluster Reference Guide/How-to
 - The best guide I've found so far, well written:
  - Deployment Guide for SRX Series Services Gateways in Chassis Cluster Configuration
  - https://kb.juniper.net/library/CUSTOMERSERVICE/GLOBAL_JTAC/NT260/SRX_HA_Deployment_Guide.pdf

### Clif notes
 - `set chassis cluster cluster-id 1 node 0 reboot`
 - `set chassis cluster cluster-id 1 node 1 reboot`
 - Fabric ports must be configured for all SRXes, but Control ports and management (fxp0) are generally fixed and different on each model.


### SRX Chassis Disable
`set chassis cluster disable reboot`

### Enable v6 flow (requires reboot)
`set security forwarding-options family inet6 mode flow-based `

## all
### EX switches (et al - Ignore Managment link down)
`set chassis alarm management-ethernet link-down ignore`

### Clean up system alerts
```
request system configuration rescue save
request system snapshot slice alternate
```

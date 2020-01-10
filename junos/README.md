# BreadBoxNet : JunOS Tips
***

## SRX
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

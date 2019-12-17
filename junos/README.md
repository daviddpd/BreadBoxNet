# BreadBoxNet : JunOS Tips
***

## SRX
### SRX Chassis Disable
`set chassis cluster disable reboot`

## all
### EX switches (et al - Ingore Managment link down)
`set chassis alarm management-ethernet link-down ignore`

### Clean up system alerts
```
request system configuration rescue save
request system snapshot slice alternate
```

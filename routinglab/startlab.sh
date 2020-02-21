#!/bin/sh

vms=`vm list | awk '{print $1}' | grep -E '^(gw|nx)' | xargs `
for vm in $vms; do 
	echo " VM: $vm "
	vm start $vm
	sleep 10
done

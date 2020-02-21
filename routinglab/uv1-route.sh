wanbr=`ifconfig | grep -B 1 vm-LABWAN0 | head -1 | awk -F : '{print $1}'`
ifconfig $wanbr inet 172.16.0.21/30 up
route add -net 172.16.0.0/30  172.16.0.21
route add -net 172.16.0.4/30  172.16.0.21
route add -net 172.16.0.8/30  172.16.0.21
route add -net 172.16.0.12/30  172.16.0.21
route add -net 172.16.0.16/30  172.16.0.21
route add -net 10.255.0.0/16 172.16.0.21

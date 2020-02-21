#!/bin/sh

h=`hostname | sed -E 's/\./-/g' | sed -E 's/-dpdtech-com//g'`
echo $h

cp -v bird-srv-mesh-${h}.conf /usr/local/etc/bird.conf
cp -v rc.conf.local-${h} /etc/rc.conf.local 
echo 'apache24_enable="YES"' > /etc/rc.conf.d/apache24
echo 'bird_enable="YES"' > /etc/rc.conf.d/bird


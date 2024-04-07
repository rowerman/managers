#!/bin/bash
make clean
sudo rmmod mod_firewall_pre_routing
sudo rmmod mod_firewall_post_routing
sudo rmmod mod_firewall_local_out
sudo rmmod mod_firewall_local_in
cd ./pre_routing
make clean
make
cp *.o ../
cp *.ko ../
cd ../post_routing
make clean
make
cp *.o ../
cp *.ko ../
cd ../local_out
make clean
make
cp *.o ../
cp *.ko ../
cd ../local_in
make clean
make
cp *.o ../
cp *.ko ../
cd ../
make
sudo insmod mod_firewall_pre_routing.ko
sudo insmod mod_firewall_post_routing.ko
sudo insmod mod_firewall_local_out.ko
sudo insmod mod_firewall_local_in.ko

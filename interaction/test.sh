#!/bin/sh
set -e
echo basic test
./test1.py $1 $2
echo ticks test
./test2.py $1 $2
echo flag test
./test3.py $1 $2

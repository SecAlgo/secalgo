#!/bin/bash

PY_NAME=ns_sk_fixed_python.py # name of python script to time
OUT_FILE=time_output.txt      # name of output file
EXIT_STATUS=0                 # status code at exit
LOOPS=1                       # number of times to run protocol
RUN_COUNT=10                  # number of times to run measurement
: > $OUT_FILE

if [ -n "$1" ]
then
    RUN_COUNT=$1
fi

if [ -n "$2" ]
then
    LOOPS=$2
fi

echo "Beginning time measurement of Python NS-SK:"

echo >> $OUT_FILE

for ((a=1; a <= RUN_COUNT; a++))
do

    time (python3 $PY_NAME $LOOPS) 2>> $OUT_FILE
    
    echo >> $OUT_FILE
    
    echo "----------------------------------------------" >> $OUT_FILE

    echo >> $OUT_FILE
done
echo "Test done. Results written to time_output.txt."

exit $EXIT_STATUS

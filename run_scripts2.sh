#!/bin/bash

for i in {21..29}
do
    echo "Processing output_${i}.log file..."
    start=`date +%s`
    python3 chains.py output_${i}.log >> chains_${i}.txt
    end=`date +%s`

    runtime=$((end-start))
    echo "Execution time for output_${i}.log : $runtime"
done
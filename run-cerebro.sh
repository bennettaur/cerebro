#!/bin/bash

# Usage:
# ./run-cerebro.sh </path/target_file.txt> </path/cerebro.py> <cerebro_concurrency> <first_port> <last_port> <increment_port> <output_filename>

# Example:
# ./run-cerebro.sh /opt/test_ip.txt /opt/cerebro.py 1000 1 65535 1000 range1

if [ $# != 7 ]; then
	echo "Usage:"
	echo "./run-cerebro.sh </path/target_file.txt> </path/cerebro.py> <cerebro_concurrency> <first_port> <last_port> <increment_port> <output_filename>"
	echo ""
	echo "Example:"
	echo "./run-cerebro.sh /opt/test_ip.txt /opt/cerebro.py 1000 1 65535 1000 range1"
	exit
fi

targets=$1
cerebro_path=$2
cerebro_con=$3
start_port=$4
end_port=$5
inc_port=$6
output_file=$7

for port in `seq $start_port $inc_port $end_port`;
do
	scan_start_port=$port
	scan_end_port=$(($scan_start_port+$(($inc_port-1))))
	if [ $scan_end_port > 65535 ]; then
		scan_end_port1=65535
	fi
	echo "[*] Scanning Ports $scan_start_port-$scan_end_port:"
	python $cerebro_path -i $targets -p $scan_start_port-$scan_end_port -c $cerebro_con -s -v
	mv results.csv $output_file-results-$scan_start_port-$scan_end_port.csv
done

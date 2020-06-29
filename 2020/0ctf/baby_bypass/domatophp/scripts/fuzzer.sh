#!/bin/bash

NODE=queue
FUZZDIR=/mnt/fuzz
TIMEOUT=3
NFILES=10

export ASAN_OPTIONS=detect_leaks=0
export USE_ZEND_ALLOC=0

mkdir -p $FUZZDIR/$NODE
mkdir -p $FUZZDIR/crashes

while true; do
	/domatophp/generator.py --output_dir $FUZZDIR/$NODE --no_of_files $NFILES
	if [ $(ls $FUZZDIR/$NODE | wc -l) -eq 0 ]; then
		echo "Waiting for more tests..."
		sleep 2
		continue
	fi

	TEST=$(ls $FUZZDIR/$NODE | head -n1)

	echo -n "Testing $TEST: "

	OUTPUT=$(timeout -s SIGTERM $TIMEOUT php -c /etc/php.ini $FUZZDIR/$NODE$TEST 2>&1)
	RET=$?

	if [ $RET -ne 0 ]; then

		if [ $RET -eq 255 ]; then
			echo "EXCEPTION"
			rm $FUZZDIR/$NODE/$TEST
			continue
		fi

		if [ $RET -eq 124 ]; then
			echo "TIMEOUT"
			rm $FUZZDIR/$NODE/$TEST
			continue
		fi

		if [ $RET -eq 153 ]; then
			echo "MEMORY LEAK"
			rm $FUZZDIR/$NODE/$TEST
			continue
		fi

		if [ $(echo "$OUTPUT" | grep "Allowed memory size of" | wc -l) -gt 0 ]; then
			echo "OOM"
			rm $FUZZDIR/$NODE/$TEST
			continue
		fi

		if [ $(echo "$OUTPUT" | grep "AddressSanitizer failed to allocate" | wc -l) -gt 0 ]; then
			echo "OOM"
			rm $FUZZDIR/$NODE/$TEST
			continue
		fi

		if [ $(echo "$OUTPUT" | grep ": Assertion " | wc -l) -gt 0 ]; then
			echo "ASSERTION"
			rm $FUZZDIR/$NODE/$TEST
			continue
		fi

		echo -e "\e[31;1mCRASH (ret:$RET)\e[0m"
		mv $FUZZDIR/$NODE/$TEST $FUZZDIR/crashes/$TEST

	else

		echo "OK"
		rm $FUZZDIR/$NODE/$TEST

	fi

	sleep 0.5

done

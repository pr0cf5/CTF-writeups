#!/bin/bash

CRASHDIR="/mnt/fuzz/crashes/"
BINDIR="/mnt/fuzz/crashbins/"

for SAMPLE in $(ls $CRASHDIR/*); do

	RIP=$(gdb php -c /etc/php.ini -ex "run $SAMPLE" -ex "p \$rip" -ex "quit" 2>&1 | egrep "=> 0x[0-9a-f]+" | sed 's/=> //g')
	if [ "$RIP" == "" ]; then
		RIP="nocrash"
	fi

	if [ ! -d "$RIP" ]; then
		mkdir $BINDIR/$RIP
	fi

	cp $SAMPLE $BINDIR/$RIP/

done
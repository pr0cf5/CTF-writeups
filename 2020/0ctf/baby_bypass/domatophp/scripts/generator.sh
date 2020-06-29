#!/bin/bash

RED="\e[31;1m"
GREEN="\e[32;1m"
BLUE="\e[34;1m"
PURPLE="\e[35;1m"
DEFAULT="\e[0m"

while true; do

	clear

	echo ""
	echo "Status:"
	echo "----------------------------"

	for node in $(ls /fuzz/ | grep -v crash); do

		COUNT=$(ls -l /fuzz/$node 2>/dev/null | grep -v total | wc -l)

		echo -e " > $BLUE$node$DEFAULT queue: $GREEN$COUNT$DEFAULT"

		if [ $COUNT -lt 200 ]; then

			echo -e "   - ${PURPLE}generating more...$DEFAULT"
			python3 /root/domato/php/generator.py --output_dir /fuzz/$node/ --no_of_files 1000 >/dev/null 2>&1 &

		fi

	done
	echo "----------------------------"

	NUMCRASHES=$(ls /fuzz/crashes/ | wc -l)
	echo ""
	echo -e "Crashes: $RED$NUMCRASHES$DEFAULT"
	echo ""

	sleep 3

done

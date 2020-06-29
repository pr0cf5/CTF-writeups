#!/bin/sh
sudo docker run -it -v $(pwd)/fuzz:/mnt/fuzz babybypass "/domatophp/scripts/fuzzer.sh"

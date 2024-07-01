#!/bin/bash

# set target and outgoing interface
TARGET=$1
OUTGOING_INTERFACE=$2
CURL_HOST=$3
TARGET_PCAP="bitflipper_${TARGET}_${CURL_HOST}.pcap"
REPORT="bitflipper_${TARGET}_${CURL_HOST}_$(date +%Y-%m-%d-%H:%M:%S).txt"

if [ -z "$CURL_HOST" ]
then
    echo "Usage: $0 <target ip> <outgoing interface> <hostname (for the host header)>"
    exit 1
fi

echo "Testing if we can make the system return our data in the path"
CURL_PATH=$(python3 -c 'print("A"*2048)')

if ! curl -v http://$TARGET/$CURL_PATH -H Host:\ $CURL_HOST -k -m 30 2>&1 | grep -v '^>' | grep -i AAAAAAAA
then
    echo "Not in the path, testing in the Host header"
    CURL_PATH=/
    CURL_HOST=$(python3 -c 'print("A"*2048)')
    if ! curl -v http://$TARGET/$CURL_PATH -H Host:\ $CURL_HOST -k -m 30 2>&1 | grep -v '^>' | grep -i AAAAAAAA
    then
        echo "Could not find any way to make curl return our AAAAAAAA data"
        exit 1
    fi
fi

echo "Executing mtr -4Tzbw -I ${OUTGOING_INTERFACE} ${TARGET}"
mtr -4Tzbw -I ${OUTGOING_INTERFACE} ${TARGET} | tee -a $REPORT
echo "(finished at $(date -Iseconds))"

echo "Starting tcpdump in the background"
tcpdump -i $OUTGOING_INTERFACE -s 0 -w $TARGET_PCAP -n host $TARGET and port 80 &
TCPDUMP=$!

echo "Doing a request every second for 600 times (at least 10 minutes)"
for i in {1..600}
do
    if ! curl -q http://$TARGET/$CURL_PATH -H Host:\ $CURL_HOST -k -m 30 >/dev/null 2>/dev/null
    then
        echo "Got a timeout, probably already triggered the bitflips"
    break
    fi
    sleep 1
    echo $i
done

echo $TCPDUMP
kill -TERM $TCPDUMP
sleep 10
echo | tee -a $REPORT
echo "Finding packets with bitflips" | tee -a $REPORT
if tcpdump -r $TARGET_PCAP -n -X src host $TARGET  | grep -i "AA[^A]AAA"
then
    echo | tee -a $REPORT
    echo "Bitflips found!" | tee -a $REPORT
    echo | tee -a $REPORT
    tcpdump -r $TARGET_PCAP -n -X src host $TARGET  | grep -B 10 -i "AA[^A]AAA" >> $REPORT
else
    echo | tee -a $REPORT
    echo "NO bitflips found" | tee -a $REPORT
fi

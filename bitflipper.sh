#!/bin/bash

# set target and outgoing interface
TARGET=$1
OUTGOING_INTERFACE=$2
HOST=$3
WHEN=$(date +%Y-%m-%d-%H:%M:%S)
TARGET_PCAP="bitflipper_${TARGET}_${HOST}_${WHEN}.pcap"
REPORT="bitflipper_${TARGET}_${HOST}_${WHEN}.txt"

REQS=(date shasum tee python3 curl grep mtr tcpdump tail cat)
REQSMISSING=0
for cmd in ${REQS[@]}; do
    if [ ! -x "$(which ${cmd})" ]; then
        echo "Prerequisite ${cmd} not found and/or not executable"
        REQSMISSING=1
    fi
done;
[ ${REQSMISSING} == 1 ] && exit 1;

echo "Running $0 $*" | tee -a $REPORT
echo "Script $(shasum $0)" | tee -a $REPORT

if [ -z "$HOST" ]
then
    echo "Usage: $0 <target ip> <outgoing interface> <hostname (for the host header)>"
    exit 1
fi

echo "Testing if we can make the system return our data in the path"
CURL_PATH=$(python3 -c 'print("A"*2048)')
CURL_HOST=$(python3 -c 'print("C"*2048)')

if ! curl -v http://$TARGET/$CURL_PATH -H Host:\ $CURL_HOST -k -m 30 2>&1 | grep -v '^>' | grep -i '\(AAAAAAAA\)\|\(CCCCCCCC\)' >/dev/null
then
    echo "Not working with CCCC in host and AAAA in path, trying with the correct host"
    CURL_HOST=$HOST
    if ! curl -v http://$TARGET/$CURL_PATH -H Host:\ $CURL_HOST -k -m 30 2>&1 | grep -v '^>' | grep -i AAAAAAAA >/dev/null
    then
        echo "Could not find any way to make curl return our AAAA data"
        exit 1
    fi
fi
echo | tee -a $REPORT
echo "Using the following request: curl http://$TARGET/$CURL_PATH -H Host:\ $CURL_HOST -k -m 30" | tee -a $REPORT
echo | tee -a $REPORT

if mtr --help | grep -- -I
then
    MTR_INTERFACE="-I ${OUTGOING_INTERFACE}"
else
    MTR_INTERFACE=""
fi
echo "Executing mtr -4Tzbw ${MTR_INTERFACE} ${TARGET}"
mtr -4Tzbw ${MTR_INTERFACE} ${TARGET} | tee -a $REPORT
echo "(finished at $(date -Iseconds))"

echo "Executing mtr -4zbw ${MTR_INTERFACE} ${TARGET}"
mtr -4zbw ${MTR_INTERFACE} ${TARGET} | tee -a $REPORT
echo "(finished at $(date -Iseconds))"

echo "Starting tcpdump in the background"
tcpdump -i $OUTGOING_INTERFACE -s 0 -w $TARGET_PCAP -n host $TARGET and port 80 &
TCPDUMP=$!
sleep 1
tail -f $TARGET_PCAP | tcpdump -r - -n -X src host $TARGET | grep -i '\(AA[^A ]AA\)\|\(CC[^C ]CC\)' &
TCPDUMP_TAIL=$!

RUNNING=1
trap ctrl_c INT

function ctrl_c() {
        echo "** Got CTRL-C"
        RUNNING=0
}

echo "Doing a request for 1000 times with 1 second sleep in between (at least 10 minutes). You can CTRL+C if you see a bitflip packet in the output"
for i in {1..1000}
do
    if [ "$RUNNING" != "1" ]
    then
        break
    fi

    if ! curl -q http://$TARGET/$CURL_PATH -H Host:\ $CURL_HOST -k -m 30 >/dev/null 2>/dev/null
    then
        echo "Got a timeout, probably already triggered the bitflips"
    break
    fi
    sleep 1
    if [ $(($i % 10)) == 0 ]
    then
        echo "Done $i requests"
    fi
done

echo $TCPDUMP
if [ "$RUNNING" == "1" ]
then
    kill -TERM $TCPDUMP
    kill -TERM $TCPDUMP_TAIL
fi

echo
echo "Waiting 10 seconds to settle down the pcaps"
sleep 10
echo | tee -a $REPORT
echo "Finding packets with bitflips" | tee -a $REPORT
if tcpdump -r $TARGET_PCAP -n -X src host $TARGET  | grep -i '\(AA[^A ]AA\)\|\(CC[^C ]CC\)'
then
    echo "Bitflips found!" | tee -a $REPORT
    echo | tee -a $REPORT
    tcpdump -r $TARGET_PCAP -n -X src host $TARGET  | grep -B 10 -A 10 -i '\(AA[^A ]AA\)\|\(CC[^C ]CC\)' >> $REPORT
else
    echo "NO bitflips found" | tee -a $REPORT
fi

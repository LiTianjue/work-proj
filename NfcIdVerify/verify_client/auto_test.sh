#!/bin/bash
ok=0
bad=0
count=1000
aver=0
for((i=0; i <1000;i++))
do
	./nfc_client -h 172.16.2.198 -p 9019 -s 201503150003 $2>/dev/null
	if [ $? == 0 ]
	then
		ok=$(($ok+1))
	else
		bad=$(($bad+1))
	fi
done


echo "--------------------------"
echo "Cost ${SECONDS}"
echo "Success ${ok} Fail ${bad}"
num=`echo "sclae=2; ${count} / ${SECONDS}" | bc`
echo "Average ${num} times / s"
echo "--------------------------"

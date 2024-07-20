#!/bin/bash

FOLDER=results
TARGETS=("CVE-2016-4557" "CVE-2016-8655" "CVE-2017-10661" "CVE-2017-11176" "CVE-2017-15649" "CVE-2018-6555" "CVE-2016-0728" "CVE-2017-6074" "CVE-2017-8890")
#TARGETS=("CVE-2021-22555" "CVE-2022-2588")
NUM=1000
CORE_NUM=2
MEM_SIZE=2

for target in ${TARGETS[@]};
do
        res_path=$FOLDER/"$target"-idle-busy
        echo $target;
        echo $res_path
        python vuln_tester.py -c $target -n $NUM -r $res_path -C $CORE_NUM -m $MEM_SIZE -nl #-l busy
        pkill -f "./startvm"
done
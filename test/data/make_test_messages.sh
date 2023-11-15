#!/bin/bash
# Copyright (c) 2023, Laurence Lundblade. All rights reserved.


rm -f test_messages.[ch]


cat << EOM > test_messages.c
/* This file is created by make_test_messages.sh from CBOR diag files */
EOM

cp test_messages.c test_messages.h

for i in *.diag;
do
  j=${i%.*}
  diag2cbor.rb $i > $j
  fgrep -q '***' $j
  st=$?
  if [ $st == 0 ];
  then
      echo "Error processing file \"$j\""
      exit
  fi

  xxd -c 8 -i $j > $j.tmp
  size=`grep 'unsigned int' $j.tmp | sed 's/^.*=\ \([0-9]*\);/\1/'`
  grep 'unsigned char' $j.tmp | sed 's/^unsigned/extern const unsigned/' | \
                                sed 's/].*/\];/' | \
                                sed "s/\[\]/\[$size\]/" >> test_messages.h
  cat $j.tmp | sed 's/^unsigned/const unsigned/' >> test_messages.c
  echo  >> test_messages.c
  echo  >> test_messages.h


  rm $j $j.tmp

done


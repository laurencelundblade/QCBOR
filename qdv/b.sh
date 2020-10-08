#!/bin/bash


function foo {
    local prefix=$1 # the prefix is the first argument
    local theset=$2 # the set left to process is the second argument
  
    # Output the new prefix
    echo "$prefix"

    # Loop over each item in the set adding it to the prefix
    # All items eventually get added to the prefix and the set
    # goes to nothing. Prefixes are what is output
    for i in $theset; do

        # Make a new prefix by appending the item from the set to it
        local newprefix="$prefix ${i}" 

        # Update the set by removing one more item from it 
        if [[ ! $theset = *[\ ]* ]]; then
            theset=""
        else
            theset=${theset#* }
        fi

        if [[ ! -z "$theset" ]]; then
           # The set is not empty, recurse to process it
           foo "$newprefix" "$theset"
        else
           # The set is empty, just output the new prefix
           echo "$newprefix"
        fi

        #echo "set:" $set
        #echo "pre:" $pre
    done
}

make clean
make -f qdv/Makefile.min decode_min encode_min
qdv/sizes.sh decode_min 
qdv/sizes.sh encode_min

make clean
make -f qdv/Makefile.max decode_max encode_max
qdv/sizes.sh decode_max 
qdv/sizes.sh encode_max

set="-DQCBOR_DISABLE_FLOAT_HW_USE -DQCBOR_DISABLE_PREFERRED_FLOAT -DQCBOR_CONFIG_DISABLE_EXP_AND_MANTISSA"
foo "" "$set" > /tmp/b.$$

while read opts; do
   echo "$opts"
   make clean > /dev/null
   make "CMD_LINE=$opts" > /dev/null 2>&1
   ./qcbortest > /tmp/bb.$$
   grep SUMMARY /tmp/bb.$$
   #if [ $? -eq 0 ]; then
   #   echo "FAIL FAIL FAIL $opts"
   #fi
done < /tmp/b.$$


rm /tmp/b.$$


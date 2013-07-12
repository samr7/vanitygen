#!/bin/bash

# a simple bulk-wallet generator
#
# 3 arguments needed: address version, pattern, count
#
# some address versions:
# 0   Bitcoin
# 23  Primecoin
# 48  Litecoin

./vanitygen -kF compressed -X $1 $2 2>/dev/null | head -n `expr $3 \* 3` | egrep "Address|Privkey" | awk '{printf("%s ", $2); getline; printf("%s\n",$2)}'

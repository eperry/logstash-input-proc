#!/bin/bash
set -x
curl -XDELETE localhost:9200/_template/\*

for  t in `find templates -name \*.json`
do
curl -XPUT localhost:9200/_template/`basename ${t} .json` -d @${t}
done 

echo "============================================"
curl -XGET localhost:9200/_template/
echo "============================================"


#!/bin/bash
api_key='eGghpexlvMdaMm7O1fnuP6pq7HinefSEPzDbAhKi'
misp_url='https://192.168.1.50/attributes/restSearch'
curl -k -H 'Accept: application/json' -H 'Content-type: application/json' -H 'Authorization: '$api_key'' -XGET $misp_url/returnFormat:suricata/type:ip-src||ip-dst/org:CUDESO

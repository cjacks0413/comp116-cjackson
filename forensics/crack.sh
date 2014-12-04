#!/bin/bash
# default: cracking steghide password

while read w; do
       echo $w
       steghide extract -sf b.jpg -p "$w"
# uncomment below for cracking zip 
#       unzip -P "$w" lockbox.zip 
done <password.lst 
                
#!/bin/bash
t=($(echo "$(cat)"|grep -oP 'ttl=\K\d+'))
m=$(printf "%d\n" "${t[@]}"|sort -n|head -1)
for ((i=0;i<${#t[@]}-1;i++));do
if ((t[i]==m&&t[i+1]==m));then
p=$i
break
fi
done
a=$((${#t[@]}))
b=()
for ((i=0;i<a;i++));do
b+=("${t[(a+i+p+2)%a]}")
done
s=""
c=0
for ((i=0;i<${#b[@]}-4;i+=2));do
u=$((b[i]-m))
l=$((i+1<${#b[@]}?b[i+1]-m:0))
h=$(printf "%02x" $((u<<4|l)))
s+="$h"
c=$((((c+u+l)%256)&0x0f))
done
k=$((t[p-1]-m))
if ((c!=k));then
echo "Checksum mismatch. The data may be corrupted."
fi
printf %b $(printf %s "$s"|while read -r -n2 c;do printf "\x$c";done)|base64 -d -w0

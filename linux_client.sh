#!/bin/bash
ttl_values=($(echo "$(cat)" | grep -oP 'ttl=\K\d+'))
min_ttl=$(printf "%d\n" "${ttl_values[@]}" | sort -n | head -1)

for ((i=0; i<${#ttl_values[@]}-1; i++)); do
  if ((ttl_values[i] == min_ttl && ttl_values[i+1] == min_ttl)); then
    payload_end_index=$i
    break
  fi
done
echo "min ttl: $min_ttl"
arraylen=$((${#ttl_values[@]}))
for ((i=0; i<${#ttl_values[@]}-1; i++)); do
	echo -n "	${ttl_values[i]}" 
done

echo -e "\n$payload_end_index\n"

for ((i=0; i<${#ttl_values[@]}-1; i++)); do
	echo -n "	${i}" 
done
echo ""

base64_hex_array=()
for ((i=0; i<arraylen; i++)); do
	base64_hex_array+=("${ttl_values[ (arraylen+i+payload_end_index+2)%arraylen ]}")
done
echo "Final base64 array:"
printf "%d " "${base64_hex_array[@]}"
echo

base64_hex=""
checksum=0

for ((i=0; i<${#base64_hex_array[@]}-4; i+=2)); do
  upper_nibble=$((base64_hex_array[i] - min_ttl))
  if ((i+1 < ${#base64_hex_array[@]})); then
    lower_nibble=$((base64_hex_array[i+1] - min_ttl))
  else
    lower_nibble=0
  fi

  base64_hex_char=$(printf "%02x" $((upper_nibble << 4 | lower_nibble)))
  
  base64_hex+="$base64_hex_char"
  checksum=$((((checksum + upper_nibble + lower_nibble) % 256) & 0x0f ))
done
checksum_ttl=$((ttl_values[payload_end_index-1] - min_ttl))
echo -e "checksum $checksum\ngrabbed checksum:$checksum_ttl"

if ((checksum != checksum_ttl)); then
  echo "Checksum mismatch. The data may be corrupted."
fi

base64_string=$(printf %b $(printf %s "$base64_hex"|while read -r -n2 c;do printf "\x$c";done))
echo "base string: $base64_string"
decoded_string=$(echo $base64_string | base64 -d -w0)
echo "Decoded string: $decoded_string"

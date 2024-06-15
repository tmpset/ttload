# Send ICMP echo requests to the IP address 139.162.137.111 and store the TTL values in the $ttlValues array
$ttlValues = 1..NUMBER_OF_NIBBLES | ForEach-Object { ([System.Net.NetworkInformation.Ping]::new().Send('YOUR_SERVER_IP')).Options.Ttl }

# Find the minimum TTL value
$minTtl = ($ttlValues | Sort-Object)[0]

# Find the index of the first occurrence of two consecutive minimum TTL values
$pivotIndex = -1
for ($i = 0; $i -lt $ttlValues.Count - 1; $i++) {
    if ($ttlValues[$i] -eq $minTtl -and $ttlValues[$i + 1] -eq $minTtl) {
        $pivotIndex = $i
        break
    }
}

# Rearrange the TTL values based on the pivot index
$rearrangedTtlValues = @()
$arrayLength = $ttlValues.Count
for ($i = 0; $i -lt $arrayLength; $i++) {
    $rearrangedTtlValues += $ttlValues[($arrayLength + $i + $pivotIndex + 2) % $arrayLength]
}

# Extract the hidden message from the rearranged TTL values
$hiddenMessage = ""
$checksum = 0
for ($i = 0; $i -lt $rearrangedTtlValues.Count - 4; $i += 2) {
    $upperNibble = $rearrangedTtlValues[$i] - $minTtl
    $lowerNibble = if ($i + 1 -lt $rearrangedTtlValues.Count) { $rearrangedTtlValues[$i + 1] - $minTtl } else { 0 }
    $hexByte = "{0:X2}" -f ($upperNibble -shl 4 -bor $lowerNibble)
    $hiddenMessage += $hexByte
    $checksum = (($checksum + $upperNibble + $lowerNibble) % 256) -band 0x0f
}

# Verify the checksum
$checksumValue = $ttlValues[$pivotIndex - 1] - $minTtl
if ($checksum -ne $checksumValue) {
    "Checksum mismatch. The data may be corrupted."
}
else {
    # Convert the hidden message from hex to bytes
    $messageBytes = @()
    for ($i = 0; $i -lt $hiddenMessage.Length; $i += 2) {
        $byte = [Convert]::ToByte($hiddenMessage.Substring($i, 2), 16)
        $messageBytes += $byte
    }

    # Decode the hidden message from UTF-8
    $decodedMessage = [System.Text.Encoding]::UTF8.GetString($messageBytes)

    # Decode the base64-encoded message
    [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($decodedMessage))
}

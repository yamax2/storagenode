#!/bin/sh
set -e

KEY_FILE="${1:-node.pem}"

if [ ! -f "$KEY_FILE" ]; then
    echo "Error: Key file '$KEY_FILE' not found" >&2
    exit 1
fi

# Extract modulus and exponent from the private key
modulus_hex=$(openssl rsa -in "$KEY_FILE" -noout -modulus 2>/dev/null | cut -d= -f2)
exponent=$(openssl rsa -in "$KEY_FILE" -noout -text 2>/dev/null | grep "publicExponent" | sed 's/.*(\(0x[0-9a-fA-F]*\)).*/\1/')

# Convert modulus from hex to base64url
n=$(echo "$modulus_hex" | xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# Convert exponent to base64url (65537 = 0x10001 = AQAB)
if [ "$exponent" = "0x10001" ]; then
    e="AQAB"
else
    e=$(printf '%x' "$exponent" | xxd -r -p | openssl base64 -A | tr '+/' '-_' | tr -d '=')
fi

# Generate kid from key fingerprint
kid=$(openssl rsa -in "$KEY_FILE" -pubout -outform DER 2>/dev/null | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=' | cut -c1-16)

cat <<EOF
{
  "keys": [
    {
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "kid": "$kid",
      "n": "$n",
      "e": "$e"
    }
  ]
}
EOF

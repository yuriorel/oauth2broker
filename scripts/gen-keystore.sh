#!/usr/bin/env sh
# Creates keystore.p12 with a self-signed TLS certificate (alias "tls") and an RS256 signing key (alias "signing").
set -e
cd "$(dirname "$0")/.."
KEYTOOL="${JAVA_HOME:+$JAVA_HOME/bin/}keytool"
PASSWORD="${KEYSTORE_PASSWORD:-changeit}"
rm -f keystore.p12

"$KEYTOOL" -genkeypair -alias tls -keyalg RSA -keysize 2048 -validity 365 \
  -dname "CN=localhost" -ext "SAN=dns:localhost,ip:127.0.0.1" \
  -storetype PKCS12 -keystore keystore.p12 -storepass "$PASSWORD"

"$KEYTOOL" -genkeypair -alias signing -keyalg RSA -keysize 2048 -validity 365 \
  -dname "CN=oauth2broker signing" \
  -storetype PKCS12 -keystore keystore.p12 -storepass "$PASSWORD"

echo "Created keystore.p12"

# Creates keystore.p12 with a self-signed TLS certificate (alias "tls") and an RS256 signing key (alias "signing").
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$keytool = if ($env:JAVA_HOME) { Join-Path $env:JAVA_HOME 'bin\keytool.exe' } else { 'keytool' }
$password = if ($env:KEYSTORE_PASSWORD) { $env:KEYSTORE_PASSWORD } else { 'changeit' }
Remove-Item keystore.p12 -ErrorAction SilentlyContinue

& $keytool -genkeypair -alias tls -keyalg RSA -keysize 2048 -validity 365 `
  -dname 'CN=localhost' -ext 'SAN=dns:localhost,ip:127.0.0.1' `
  -storetype PKCS12 -keystore keystore.p12 -storepass $password
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

& $keytool -genkeypair -alias signing -keyalg RSA -keysize 2048 -validity 365 `
  -dname 'CN=oauth2broker signing' `
  -storetype PKCS12 -keystore keystore.p12 -storepass $password
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Output 'Created keystore.p12'

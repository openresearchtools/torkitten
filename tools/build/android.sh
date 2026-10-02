#!/usr/bin/env bash
set -euo pipefail
mobile_version=v0.0.0-20260908204917-8b95e45f8d3e
output=/work/android
mkdir -p "$output/tools" "$output/classes"
export GOBIN="$output/tools" PATH="$output/tools:$PATH"
go install "golang.org/x/mobile/cmd/gomobile@$mobile_version"
go install "golang.org/x/mobile/cmd/gobind@$mobile_version"
cp /src/native/android/go.mod "$output/module.mod"
cd /src/native/android
go mod edit -modfile="$output/module.mod" -replace=torkitten=/src \
    -replace=github.com/jpillora/chisel=/src/third-party/chisel \
    -replace=filippo.io/age=/src/third-party/age \
    -replace=github.com/makiuchi-d/gozxing=/src/third-party/gozxing
export GOFLAGS="-mod=mod -modfile=$output/module.mod"
gomobile bind -target=android/arm64 -androidapi=26 -javapkg=org.openresearchtools.torkitten.core \
    -o "$output/torkitten-core.aar" torkitten/mobile
unzip -p "$output/torkitten-core.aar" classes.jar > "$output/core-classes.jar"
javac -source 17 -target 17 -classpath "/android-sdk/platforms/android-36/android.jar:$output/core-classes.jar" \
    -d "$output/classes" /src/native/android/MainActivity.java
cp /src/native/android/AndroidManifest.xml "$output/"
printf 'Built AAR and Java shell in %s. No APK or Android runtime compatibility claimed.\n' "$output"

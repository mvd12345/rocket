#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

mvn -q -DskipTests package
mvn -q test

mkdir -p demo/output

java -jar target/RobustaPlus-1.0-SNAPSHOT-shaded.jar \
  -cli \
  -o target/test-classes \
  -j demo/config/methodConfig.toy.json | \
  sed -E 's#(/Users|/home)/[^ ]+#/path/to#g; s#C:\\\\Users\\\\[^ ]+#C:\\\\path\\\\to#g; s#/var/[^ ]+#/path/to#g; s#/tmp/[^ ]+#/path/to#g'

#!/bin/sh
# Copies website/ to pcapmirror.freestone.net (run tools/update-website.sh first).
set -eu
cd "$(dirname "$0")/.."
scp -r website/. root@ws01.freestone.net:/webhome/pcapmirror.freestone.net/

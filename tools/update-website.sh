#!/bin/sh
# Writes the version from debian/changelog into website/index.html
# (pcapmirror.freestone.net); afterwards publish it with
# tools/deploy-website.sh.
#
#   tools/update-website.sh
#
# The download buttons need no update: they point to
# .../-/releases/permalink/latest/downloads/<filepath> (see the release job
# in .gitlab-ci.yml), which always gives the packages of the newest release.
set -eu
cd "$(dirname "$0")/.."

VERSION=$(dpkg-parsechangelog -S Version | sed -e 's/^[0-9]*://' -e 's/-[^-]*$//')
sed -i "s|<!--VERSION-->[^<]*<!--/VERSION-->|<!--VERSION-->$VERSION<!--/VERSION-->|g" website/index.html

echo "Website for pcapmirror $VERSION ready in website/"

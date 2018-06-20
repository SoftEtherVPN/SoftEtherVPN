#!/bin/bash
set -e

while IFS=$'\n\r' read -r line || [[ -n "$line" ]]; do
    echo "Text read from file: $line"
    case $line in
      BUILD_NUMBER\ *)
        BUILD_NUMBER=${line#BUILD_NUMBER }
      ;;
      VERSION\ *)
        VERSION=${line#VERSION }
      ;;
      BUILD_NAME\ *)
        BUILD_NAME=${line#BUILD_NAME }
      ;;

    esac
done < "src/CurrentBuild.txt"

VERSION=${VERSION:0:1}.${VERSION:1} # Add a colon after the first character. ("501" => "5.01")

CHANGELOG_VERSION="(0:$VERSION.$BUILD_NUMBER) $BUILD_NAME"

IFS=$'\n\r' read -r line < "debian/changelog"
if [[ $line == *$CNANGELOG_VERSION* ]]; then
  echo "debian/changelog matches src/CurrentBuild.txt"
else
  echo "debian/changelog does not match src/CurrentBuild.txt"
  exit 1
fi

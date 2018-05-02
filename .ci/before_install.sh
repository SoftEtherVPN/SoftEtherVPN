#!/bin/bash
set -eux

if [[ "${TRAVIS_OS_NAME}" == "linux" ]]; then
	sudo apt-get update
	sudo apt-get -y install debhelper
	bash .ci/build-openssl.sh > build-deps.log 2>&1 || (cat build-deps.log && exit 1)
elif [[ "${TRAVIS_OS_NAME}" == "osx" ]]; then
	brew update && brew upgrade openssl
else
	exit 1
fi

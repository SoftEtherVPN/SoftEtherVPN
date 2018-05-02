#!/bin/bash
set -eux

if [[ "${TRAVIS_OS_NAME}" == "linux" ]]; then
	export LD_LIBRARY_PATH="${HOME}/opt/lib:${LD_LIBRARY_PATH:-}"
	export CFLAGS="-I${HOME}/opt/include"
	export LDFLAGS="-L${HOME}/opt/lib"
	./configure
	make
	ldd bin/vpnserver/vpnserver
	dh build-arch
elif [[ "${TRAVIS_OS_NAME}" == "osx" ]]; then
	./configure
	make
else
	exit 1
fi

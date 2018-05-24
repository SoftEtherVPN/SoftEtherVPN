#!/bin/bash
set -eux

if [[ "${TRAVIS_OS_NAME}" == "linux" ]]; then
	export LD_LIBRARY_PATH="${HOME}/opt/lib:${LD_LIBRARY_PATH:-}"
	export CFLAGS="-I${HOME}/opt/include"
	export LDFLAGS="-L${HOME}/opt/lib"
	./configure
	make -C tmp
	ldd bin/vpnserver/vpnserver
	dh build-arch
elif [[ "${TRAVIS_OS_NAME}" == "osx" ]]; then
	./configure
	make -C tmp
else
	exit 1
fi

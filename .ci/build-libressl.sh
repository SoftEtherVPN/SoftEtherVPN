#!/bin/bash
set -eux

download_libressl () {
    if [[ ! -f "download-cache/librenssl-${LIBRESSL_VERSION}.tar.gz" ]]; then
        wget -P download-cache/ \
            "https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LIBRESSL_VERSION}.tar.gz"
    fi
}

build_libressl () {
    if [[ "$(cat ${OPENSSL_INSTALL_DIR}/.openssl-version)" != "${LIBRESSL_VERSION}" ]]; then
        tar zxf "download-cache/libressl-${LIBRESSL_VERSION}.tar.gz"
        cd "libressl-${LIBRESSL_VERSION}/"
        ./configure --prefix="${OPENSSL_INSTALL_DIR}"
        make -j $(nproc || sysctl -n hw.ncpu || echo 4) all
        make  install
        echo "${LIBRESSL_VERSION}" > "${OPENSSL_INSTALL_DIR}/.openssl-version"
    fi
}

download_libressl
build_libressl

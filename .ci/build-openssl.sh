#!/bin/bash
set -eux

download_openssl () {
    if [[ ! -f "download-cache/openssl-${OPENSSL_VERSION}.tar.gz" ]]; then
        wget -P download-cache/ \
            "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
    fi
}

build_openssl () {
    if [[ "$(cat ${OPENSSL_INSTALL_DIR}/.openssl-version)" != "${OPENSSL_VERSION}" ]]; then
        tar zxf "download-cache/openssl-${OPENSSL_VERSION}.tar.gz"
        cd "openssl-${OPENSSL_VERSION}/"
        ./config shared --prefix="${OPENSSL_INSTALL_DIR}" --openssldir="${OPENSSL_INSTALL_DIR}" -DPURIFY
        make all install_sw
        echo "${OPENSSL_VERSION}" > "${OPENSSL_INSTALL_DIR}/.openssl-version"
    fi
}


download_openssl
build_openssl

#!/bin/bash

set -eux

tar --exclude=.git --transform "s//SoftEtherVPN-${APPVEYOR_REPO_TAG_NAME}\//" -czf /tmp/softether-vpn-src-${APPVEYOR_REPO_TAG_NAME}.tar.gz . 
appveyor PushArtifact /tmp/softether-vpn-src-${APPVEYOR_REPO_TAG_NAME}.tar.gz


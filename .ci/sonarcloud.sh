#!/bin/sh
set -eu

RUN_SONARCLOUD="${RUN_SONARCLOUD:-0}"

if [ "${RUN_SONARCLOUD}" = "1" ] && [ ! -z ${SONAR_TOKEN+x} ]; then
   ./configure
   build-wrapper-linux-x86-64 --out-dir bw-output make -C build
   sonar-scanner -Dsonar.projectKey=SoftEtherVPN_SoftEtherVPN -Dsonar.organization=softethervpn -Dsonar.sources=. -Dsonar.cfamily.build-wrapper-output=bw-output -Dsonar.host.url=https://sonarcloud.io -Dsonar.login=${SONAR_TOKEN}
else
    echo "Skipping sonar-scan because \$RUN_SONARCLOUD != \"1\" or \$SONAR_TOKEN is not set"
fi

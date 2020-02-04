#!/bin/sh
set -eu

RUN_COVERITY="${RUN_COVERITY:-0}"

export COVERITY_SCAN_PROJECT_NAME="SoftEtherVPN/SoftEtherVPN"
export COVERITY_SCAN_BRANCH_PATTERN="master"
export COVERITY_SCAN_NOTIFICATION_EMAIL="chipitsine@gmail.com"
export COVERITY_SCAN_BUILD_COMMAND_PREPEND="./configure"
export COVERITY_SCAN_BUILD_COMMAND="make -C tmp"

if [ "${RUN_COVERITY}" = "1" ]; then
    # Ignore exit code, script exits with 1 if we're not on the right branch
    curl -s "https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh" | bash || true
else
    echo "Skipping coverity scan because \$RUN_COVERITY != \"1\""
fi

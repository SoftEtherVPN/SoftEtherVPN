#!/bin/sh

set -eux

echo -n | ./build/vpntest s | grep -Fq 'NO MEMORY LEAKS'
echo -n | ./build/vpntest c | grep -Fq 'NO MEMORY LEAKS'
echo -n | ./build/vpntest b | grep -Fq 'NO MEMORY LEAKS'

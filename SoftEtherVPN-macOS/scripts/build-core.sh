#!/bin/sh
# Build the SoftEther core and the C bridge for the macOS client into
# SoftEtherVPN-macOS/build-macos (what App/project.yml links against).
#
# Needs: Xcode command line tools, and
#   brew install cmake pkg-config openssl@3 libsodium
set -eu

HERE=$(cd "$(dirname "$0")/.." && pwd)
BUILD="$HERE/build-macos"

cmake -S "$HERE" -B "$BUILD" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_OSX_ARCHITECTURES=arm64 \
	-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0 \
	-DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"

cmake --build "$BUILD" -j "$(sysctl -n hw.ncpu)"

# Routing / DNS logic unit test (no VPN server needed)
"$BUILD/se_plan_test"

echo
echo "Built: $BUILD"
echo "libcedar / libmayaqua link against Homebrew's OpenSSL and libsodium:"
otool -L "$BUILD/softether-core/libcedar.dylib" "$BUILD/softether-core/libmayaqua.dylib" | grep -E "ssl|crypto|sodium" || true
echo "Those have to be bundled and re-signed (or linked statically) before the app can be distributed; see README.md."

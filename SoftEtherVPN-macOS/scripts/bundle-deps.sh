#!/bin/sh
# Make a bundle's Frameworks folder self-contained.
#
#   bundle-deps.sh <Frameworks dir> [codesign identity]
#
# libcedar / libmayaqua link against Homebrew's OpenSSL and libsodium by
# absolute path. This copies every non-system library they need (recursively)
# next to them, rewrites the references to @rpath, and re-signs what it
# touched. Runs as an Xcode build phase for the app and the extension (see
# App/project.yml); the identity defaults to the one Xcode is signing with,
# or ad-hoc ("-") outside Xcode.
set -eu

DIR=$1
IDENTITY=${2:-${EXPANDED_CODE_SIGN_IDENTITY:-"-"}}

[ -d "$DIR" ] || { echo "bundle-deps: no such directory: $DIR"; exit 0; }
[ -n "$IDENTITY" ] || IDENTITY="-"

# Libraries the system does not provide
external_deps()
{
	otool -L "$1" | tail -n +2 | awk '{print $1}' |
		grep -E '^(/opt/homebrew|/usr/local|/opt/local)/' || true
}

changed=1
while [ "$changed" = 1 ]; do
	changed=0

	for lib in "$DIR"/*.dylib; do
		[ -f "$lib" ] || continue

		for dep in $(external_deps "$lib"); do
			name=$(basename "$dep")

			if [ ! -f "$DIR/$name" ]; then
				# Follow Homebrew's symlinks to the real file
				cp -L "$dep" "$DIR/$name"
				chmod u+w "$DIR/$name"
				install_name_tool -id "@rpath/$name" "$DIR/$name"
				changed=1
			fi

			install_name_tool -change "$dep" "@rpath/$name" "$lib"
		done
	done
done

for lib in "$DIR"/*.dylib; do
	[ -f "$lib" ] || continue

	if [ -n "$(external_deps "$lib")" ]; then
		echo "bundle-deps: $lib still refers to a library outside the bundle" >&2
		exit 1
	fi

	# A run path into the build machine would let dyld pick up a library from
	# there instead of the bundled copy
	for rp in $(otool -l "$lib" | awk '/LC_RPATH/ {f=1} f && /^ *path / {print $2; f=0}'); do
		case "$rp" in
		@*) ;;
		*) install_name_tool -delete_rpath "$rp" "$lib" ;;
		esac
	done

	if [ "$IDENTITY" = "-" ]; then
		codesign --force --sign - "$lib"
	else
		codesign --force --options runtime --timestamp --sign "$IDENTITY" "$lib"
	fi
done

echo "bundle-deps: $(ls "$DIR" | tr '\n' ' ')"

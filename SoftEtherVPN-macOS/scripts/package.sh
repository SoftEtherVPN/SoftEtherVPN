#!/bin/sh
# Build, sign, notarize and package the app for distribution outside the Mac
# App Store.
#
#   package.sh <notarytool keychain profile>
#
# Needs a paid Apple Developer account with:
#   - a "Developer ID Application" certificate in the login keychain
#   - Developer ID provisioning profiles for the app and the tunnel extension
#     that include the Network Extension and System Extension capabilities
#   - DEVELOPMENT_TEAM set in App/project.yml
#   - notarization credentials stored once with
#       xcrun notarytool store-credentials <profile> --apple-id <id> --team-id <team>
#
# NOT YET RUN: written without access to a Mac or a developer account.
set -eu

PROFILE=${1:?usage: package.sh <notarytool keychain profile>}
HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT="$HERE/build-macos/dist"
ARCHIVE="$OUT/SoftEtherVPN.xcarchive"
APP="$OUT/export/SoftEther VPN.app"
DMG="$OUT/SoftEtherVPN.dmg"

"$HERE/scripts/build-core.sh"

cd "$HERE/App"
xcodegen generate

rm -rf "$OUT"
mkdir -p "$OUT"

TEAM=$(xcodebuild -project SoftEtherVPN.xcodeproj -scheme SoftEtherVPN -configuration Release \
	-showBuildSettings | sed -n 's/^ *DEVELOPMENT_TEAM = //p' | head -1)
[ -n "$TEAM" ] || { echo "Set DEVELOPMENT_TEAM in App/project.yml"; exit 1; }

xcodebuild -project SoftEtherVPN.xcodeproj -scheme SoftEtherVPN -configuration Release \
	-archivePath "$ARCHIVE" -allowProvisioningUpdates archive

cat > "$OUT/ExportOptions.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>method</key>
	<string>developer-id</string>
	<key>signingStyle</key>
	<string>automatic</string>
	<key>teamID</key>
	<string>$TEAM</string>
</dict>
</plist>
PLIST

xcodebuild -exportArchive -archivePath "$ARCHIVE" -exportPath "$OUT/export" \
	-exportOptionsPlist "$OUT/ExportOptions.plist" -allowProvisioningUpdates

# Everything inside must carry the hardened runtime and a secure timestamp
codesign --verify --deep --strict --verbose=2 "$APP"

# Notarize the app, staple, then wrap it in a disk image and do the same
ditto -c -k --keepParent "$APP" "$OUT/app.zip"
xcrun notarytool submit "$OUT/app.zip" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$APP"

STAGE="$OUT/dmg"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
hdiutil create -volname "SoftEther VPN" -srcfolder "$STAGE" -ov -format UDZO "$DMG"

IDENTITY=$(codesign -dvv "$APP" 2>&1 | sed -n 's/^Authority=\(Developer ID Application.*\)$/\1/p' | head -1)
codesign --force --timestamp --sign "$IDENTITY" "$DMG"

xcrun notarytool submit "$DMG" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$DMG"
spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"

echo "Done: $DMG"

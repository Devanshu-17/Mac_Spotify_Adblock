#!/bin/sh
path="/Applications/Spotify.app"
libpath="$path/Contents/Frameworks/Chromium Embedded Framework.framework"
cert="$*"
[ -f "$libpath/Chromium Embedded Framework.orig" ] && {
	echo "Adblock is already installed"
	exit 1
}
gcc -dynamiclib -o "Chromium Embedded Framework" spotiblock.c &&
codesign --sign "$cert" "Chromium Embedded Framework" &&
mv -v "$libpath/Chromium Embedded Framework"{,.orig} &&
mv -v "Chromium Embedded Framework" "$libpath" &&
codesign --force --deep --sign "$cert" "$path"

#!/bin/bash
# use: ./debian/dch-generate.sh > ./debian/changelog
# desc: quick and dirty (emphasis on dirty) debian changelog generator for SoftEtherVPN
#
# Copyright (c) 2014 Sahal Ansari (github@sahal.info)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.

# warning: the following file has CRLF line endings (Windows)
# the location of the following file is relative to this script
cbuild="../src/CurrentBuild.txt"

# required for debian packaging
package="softether-vpn"
status="UNRELEASED"
# timezone in +hh:mm from UTC (+9 UTC)
tzone="+09:00"
# static changelog entry
entry="* See: http://www.softether.org/5-download/history"

# are you a debian maintainer?
if [ -z "$DEBFULLNAME" ]; then
	DEBFULLNAME="John Q. Sample"
fi
if [ -z "$DEBEMAIL" ]; then
	DEBEMAIL="tamade@example.org"
fi

# where am i located? in $DIR, of course!
DIR="$( cd "$( dirname "$0" )" && pwd )"
cd "$DIR"
# check if debian/changelog exists, check if $cbuild exists
if [ ! -e ./changelog ]; then
	echo "Am I in debian/? I can't find changelog"
	exit 1
fi
if [ ! -e "$cbuild" ]; then
	echo "This doesn't look like the SoftEtherVPN source tree.  I can't find ""$cbuild"
	exit 1
fi

# version and date info from $cbuild are put into array ${cbuildarray[@]}
# build "${cbuildarray[0]}", major version "${cbuildarray[1]}",
# release type "${cbuildarray[2]}", and  date "${cbuildarray[3]}"
while IFS=$'\r\n' read -r line_data; do
        cbuildarray[i]="${line_data##*[A-Z]\ }"
	((++i))
done < "$cbuild"

# "${cbuildarray[1]}" is converted from "406" to "4.06" using GNU awk
majorversion="$(echo "${cbuildarray[1]}" | awk '{sub(/[0-9]/,"&.",$0);print $0}')"

# "${cbuildarray[3]}" is split and the second half is converted from
# from "131655" to "13:16:55" using GNU awk then it's put back together
# (like humpty dumpty) and sent to GNU date for conversion to UTC
time="$(echo "${cbuildarray[3]#*_}" | awk '{gsub(/[0-9][0-9]/,"&:",$0);print $0}')"
date="$(date -R --date="$(echo "${cbuildarray[3]%_*}"" ""${time%?}""$tzone")")"

# print the new debian changelog
echo "$package"" (""$majorversion"".""${cbuildarray[0]}""-""${cbuildarray[2]}"") ""$status""; urgency=low"
echo
echo "  ""$entry"
echo
echo " --"" ""$DEBFULLNAME"" <""$DEBEMAIL"">  ""$date"

exit 0

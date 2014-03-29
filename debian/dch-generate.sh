#!/bin/bash
# use: ./debian/dch-generate.sh > ./debian/changelog
# desc: quick and dirty (emphasis on dirty) debian changelog generator for SoftEtherVPN
#
# Copyright (c) 2014 Sahal Ansari (github@sahal.info)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.

# note: the following file has CRLF line endings (Windows)
cbuild="../src/CurrentBuild.txt"

# required for debian packaging
package="softether-vpn"
status="UNRELEASED"
# timezone in +hh:mm from GMT
# assuming the orij. author is in Japan: +9 GMT
tzone="+09:00"
# builder name, builder email
builder="John Q. Sample"
email="tamade@example.org"
# static changelog entry
entry="* See: http://www.softether.org/5-download/history"

# check if ./changelog exists, check if $cbuild exists
if [ ! -e ./changelog ]; then
	/bin/echo -ne "Are you in debian/? I can't find: ./changelog\n"
	exit 1
fi

if [ ! -e $cbuild ]; then
	/bin/echo -ne "This doesn't look like the SoftEtherVPN source tree.  I can't find: src/CurrentBuild.txt\n"
	exit 1
fi

# parse version and date -- formatted in RFC 2822 format -- from ../src/CurrentBuild.txt
while IFS=$'\ ' read -r line_data; do
	cbuildarray[i]=$(echo "${line_data}"| sed -e s/\\r// -e s/.*\ //)
	((++i))
done < $cbuild

#buildnumber="${cbuildarray[0]}"
#majorversion="${cbuildarray[1]}"
#releasetype="${cbuildarray[2]}"
#unparseddate="${cbuildarray[3]}"

# "${cbuildarray[1]}" needs to be converted
# from "406" to "4.06"
# this is really ugly and requires GNU awk (afaik)
version="$(echo "$(echo "${cbuildarray[1]}" | awk '{sub(/[0-9]/,"&.",$0);print $0}' )"".""${cbuildarray[0]}""-""${cbuildarray[2]}")"

# "${cbuildarray[3]}" \needs\ to be converted
# from "20140321_131655" to "20140321 13:16:55+0900"
# this is really really ugly and requires GNU date and GNU awk (afaik)
convertformat="$(echo "$(echo "${cbuildarray[3]}" | sed s/_.*//)"" ""$(echo "${cbuildarray[3]}" | sed s/.*_// | awk '{gsub(/[0-9][0-9]/,"&:",$0);print $0}' | sed s/\:$//)")"
# now we send $convertformat and $tzone to `date` and have it automagically reformat it for us
date="$(date -R --date="$(echo "$convertformat""$tzone")")"

# print the new debian changelog
/bin/echo -ne "$package ($version) $status; urgency=low\n\n  $entry\n\n -- $builder <$email>  $date\n"

exit 0

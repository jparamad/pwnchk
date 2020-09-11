#!/usr/bin/python
# PwnChk - by John Paramadilok (2020.09)
# This script checks sha1 hashed passwords against those identified
# in HIBP be compromised.
#
# Dependencies:
#   - HIBP API, haveibeenpwned.com
#   - os.subprocess uses shred
#   - requests package
#
# Notes:
#   v.0.1 - Initial code development
#
# Menu Options:
#    add      Adds passwd to list
#    del      Deletes list
#    h        Displays help menu
#    q        Quit program
#    num      Displays number of entries in list
#    run      Runs program
#
# Output:
#   run - evaluates hashed file list against HIBP API
#       >> Searching db for (1) entries.
#       << Prefix matches (21256)
#       << Suffix matches (1)
#       << ['2DC183F740EE76F27B78EB39C8AD972A757:54230']
#   num - provides number of entries within the hashed file list
#       << Returned (1) entries.
#####################################################################

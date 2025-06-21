```text
# !/usr/bin/python
# PwnChk - by John Paramadilok (2020.09)
# This script checks hashed passwords against those identified in
# data leak databases - HaveIBeenPwned, Leak Lookup, DeHashed.
#
# Dependencies:
#   - HIBP API, haveibeenpwned.com
#   - Leak Lookup API, leak-lookup.com, Public API KEY REQUIRED
#   - DeHashed API, dehashed.com, Public API KEY REQUIRED
#   - os.system uses shred, curl
#   - requests package (pip)
#
# Notes:
#   v.0.1 - Initial code development
#   v.0.2 - Added hashed file encoding
#   v.0.3 - Added import function from sha
#           Changed from nested ifs to match
#   v.0.4 - Added features for LL, DH APIs; Updated import sha
#
# Menu Options:
#    add      Adds passwd to list
#    del      Deletes list
#    db       Change db query
#    h        Displays help menu
#    import   Import list from external sha file
#    q        Quit program
#    num      Displays number of entries in list
#    run      Runs program for HIBP
#
# Output:
#   run - evaluates hashed file list against DB API
#   num - provides number of entries within the hashed file list
#       << Returned (1) entries.
#####################################################################

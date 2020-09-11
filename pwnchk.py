#!/usr/bin/python
# PwnChk - by John Paramadilok (2020.09)
# This script checks sha1 hashed passwords against those identified
# in HIBP be compromised.
#
# Dependencies:
#   - HIBP API, haveibeenpwned.com
#   - os.system uses shred
#   - requests package
#
# Notes:
#   v.0.1 - Initial code development
#   v.0.2 - Added hashed file encoding
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

import getpass
import hashlib
import os
import requests
import base64

# Global Vars
v = 'v.0.2'
flist = './pwnchk.enc'  # Encoded Hashed list file


def fdecode_func():
    """Process Base Decoding of Log File Content"""
    with open(flist, 'r') as f:
        fcontent = f.read()
    fcontent_str = fcontent.encode('ascii')
    fde = base64.b64decode(fcontent_str)
    fd = fde.decode('ascii')
    return fd


def fencode_func(pass_hash):
    """Process Base Encoding of File Content"""
    if str(os.path.exists(flist)) == 'True':
        fd = fdecode_func()
        flist_hash = fd + '\n' + pass_hash
    else:
        flist_hash = pass_hash
    fhe = flist_hash.encode('ascii')
    fe = base64.b64encode(fhe)
    fed = fe.decode('ascii')
    f = open(flist, 'w')
    f.write(fed)
    f.close()
    print('<< Log file successfully updated.')


def hlist_func():
    """Process Base Decoding of Log File Content"""
    # with open(flist, 'r') as f:
    #     fcontent = f.read()
    hlist = fdecode_func()
    hlist = hlist.encode('ascii')
    return hlist


def add_func():
    """Adds hashed pw entries to list"""
    passwd = getpass.getpass()

    """passwd formatting and conversion to sha1"""
    md = hashlib.sha1()
    pass_str = passwd.encode('utf8')
    md.update(pass_str)
    pass_hash = md.hexdigest()
    # print('%pass_hash = ' + pass_hash)

    """Clear passwd variable"""
    # print('%passwd = ' + passwd)
    passwd = ""
    # print('%passwd = ' + passwd)

    fencode_func(pass_hash)

    # f = open(flist, 'a')
    # f.write(pass_hash + '\n')
    # f.close()


def del_func():
    """Deletes hash list"""
    if str(os.path.exists(flist)) != 'True':
        print('[ERROR: List does not exist]')
    else:
        cin = input('Are you sure you want to permanently remove the list? (y/n) ')
        if cin == 'y':
            # os.remove(flist)
            # print('<< ' + flist + ' removed.')
            os.system('shred -fuvz ' + flist)
        else:
            print('[ABORT: List removal aborted.]')



def num_func(num):
    """Displays list count"""
    if str(os.path.exists(flist)) != 'True':
        print('[ERROR: List does not exist]')
    else:
        hlist = hlist_func()
        hlist = hlist.upper()
        list = hlist.decode('utf8').strip()
        pass_list = []

        # Converts entries in list variable to list
        for i in list.split('\n'):
            pass_list.append(i)

        list_len = len(pass_list)

        if num == 0:
            print('>> Searching db for (' + str(list_len) + ') entries.')
            return pass_list
        else:
            print('>> List has (' + str(list_len) + ') entries.')


def run_func():
    """Executes list checks against HIBP API"""
    if str(os.path.exists(flist)) != 'True':
        print('[ERROR: List does not exist]')
    else:
        num=0
        pass_list = num_func(num)
        m = 0
        for j in pass_list:
            prefix = j[:5]      # Based on HIBP API k-Anonymity model
            suffix = j[-35:]    # To perform checks against returned values

            resp = requests.get('https://api.pwnedpasswords.com/range/' + prefix).text

            print('<< Prefix matches (' + str(len(resp)) + ')')
            resp_list = []
            for i in resp.split():
                resp_list.append(i)
            r = []
            r = [x for x in resp_list if suffix in x]
            print('<< Suffix matches (' + str(len(r)) + ')')
            print('<< ' + str(r))


def help_func():
    """Displays Main Help Menu"""
    print('Menu Options:')
    print('  add      Adds passwd to list')
    print('  del      Deletes list')
    print('  h        Displays help menu')
    print('  q        Quit program')
    print('  num      Displays number of entries in list')
    print('  run      Runs program')


def menu_func():
    """Runs Menu-based Interface"""
    cin = input('pwnchk>> ')
    while cin != 'quit':
        if cin == 'add':
            add_func()
        elif cin == 'del':
            del_func()
        elif cin == 'num':
            num = 1
            num_func(num)
        elif cin == 'run':
            run_func()
        elif cin == 'h':
            help_func()
        else:
            print('Invalid command. Enter \'h\' to display help menu.')
        cin = input('pwnchk>> ')


def ver_func ():
    """Displays Code Version"""
    print('[pwnchk-' + v + ']')


def main():
    """Main Function"""
    ver_func()
    menu_func()


if __name__ == '__main__':
    main()
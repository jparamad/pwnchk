#!/usr/bin/python
# PwnChk - by John Paramadilok (2020.09)
# This program checks passwords against those identified in HIBP to
# be compromised.
#
# Dependencies:
#   - os.subprocess uses shred
#   - requests package
#
# Notes:
#   v.0.1 - Initial code development
#####################################################################

import getpass
import hashlib
import os
import requests
import base64
import subprocess

# Global Vars
v = 'v.0.1'
flist = './pwnchk.txt'  # Hashed list file


def fdecode_func():
    """Process Base Decoding of Log File Content"""
    with open(flist, 'r') as f:
        fcontent = f.read()
    fcontent_str = fcontent.encode('ascii')
    fd = base64.b64decode(fcontent_str)
    fdd = fd.decode('ascii')
    return fdd


def fencode_func(log_data, fnew):
    """Process Base Encoding of File Content"""
    if (str(os.path.exists(flist)) == 'True') and (fnew == 0):
        fdd = fdecode_func()
        fd = fdd + log_data
    else:
        fd = log_data
    fde = fd.encode('ascii')
    fe = base64.b64encode(fde)
    fed = fe.decode('ascii')
    f = open(flist, 'w')
    f.write(fed)
    f.close()
    print('<< Log file successfully updated.')


def hlist_func():
    """Process Base Decoding of Log File Content"""
    with open(flist, 'r') as f:
        fcontent = f.read()
    hlist = fcontent.encode('ascii')
    return hlist


def add_func():
    """Adds hashed pw entries to list"""
    passwd = getpass.getpass()

    """passwd formatting and conversion to sha1"""
    md = hashlib.sha1()
    pass_str = passwd.encode('utf8')
    md.update(pass_str)
    pass_hash = md.hexdigest()
    print('%pass_hash = ' + pass_hash)

    """Clear passwd entry"""
    # print('%passwd = ' + passwd)
    passwd = ""
    # print('%passwd = ' + passwd)

    f = open(flist, 'a')
    f.write(pass_hash + '\n')
    f.close()


def del_func():
    """Deletes list"""
    if str(os.path.exists(flist)) != 'True':
        print('[ERROR: List does not exist]')
    else:
        cin = input('Are you sure you want to permanently remove the list? (y/n) ')
        if cin == 'y':
            # os.remove(flist)
            # print('<< ' + flist + ' removed.')
            subprocess.run(['shred', '-fuvz', flist])
        else:
            print('[ABORT: List removal aborted.]')


def num_func():
    """Displays list count"""
    if str(os.path.exists(flist)) != 'True':
        print('[ERROR: List does not exist]')
    else:
        num = 0
        with open(flist) as f:
            for l in f:
                l = l.strip('\n')
                num += 1
        print('<< Returned (' + str(num) + ') entries.')


def run_func():
    """Executes list checks against HIBP API"""
    if str(os.path.exists(flist)) != 'True':
        print('[ERROR: List does not exist]')
    else:
        hlist = hlist_func()
        hlist = hlist.upper()
        list = hlist.decode('utf8').strip()
        pass_list = []
        for i in list.split('\n'):
            pass_list.append(i)
        list_len = len(pass_list)
        print('>> Searching db for (' + str(list_len) + ') entries.')
        m = 0
        # n = 0
        for j in pass_list:
            prefix = j[:5]
            suffix = j[-35:]

            resp = requests.get('https://api.pwnedpasswords.com/range/' + prefix).text
            # resp = requests.get('https://www.w3schools.com/python/demopage.htm').text

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
            num_func()
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
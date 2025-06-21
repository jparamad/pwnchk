#!/usr/bin/python
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

import getpass, hashlib, os, requests, base64, time, subprocess

# Global Vars
v = 'v.0.4'
flist = './pwnchk.enc'      # Encoded Hashed list file
ll_api = ''                 # TODO Replace API Key
dh_api = ''                 # TODO Replace API Key


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

    """passwd formatting and hash conversion"""
    if db_type == 2:
        md = hashlib.sha256()
    else:
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


def import_func():
    """Imports from amnesia"""
    log_path = './amnesia/amnesia.sha'

    if str(os.path.isfile(log_path)) == 'True':
        print('<< Valid file detected - Proceeding.')
        if str(os.path.isfile(flist)) == 'False':
            fencode_func(flist)
            if str(os.path.isfile(flist)) == 'True':
                print('<< File successfully imported.')
            else:
                print('[ERROR: Encoded file not found. Check for issues.]')
        else:
            print('[ERROR: Existing encoded file found - Terminating.]')
    else:
        print('[ERROR: File not found - Terminating.]')

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
            print('<< Returned (' + str(list_len) + ') entries.')


def run_func():
    global db_type

    print(db_type)
    if db_type == 1:
        llr_func()
    elif db_type == 2:
        dhr_func()
    else:
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

                print('\nRunning [' + str(m) + ']')
                m += 1
                print('<< Prefix matches (' + str(len(resp)) + ')')
                resp_list = []
                for i in resp.split():
                    resp_list.append(i)
                r = []
                r = [x for x in resp_list if suffix in x]
                print('<< Suffix matches (' + str(len(r)) + ')')
                print('<< ' + str(r))
    print('\nScan completed.')


def stat_func():
    ll_url = 'https://leak-lookup.com/api/stats'
    pyld = {'key': ll_api}

    """Display LL API Stats"""
    r = requests.post(ll_url, data=pyld).text
    print(str(r))


def llr_func():
    ll_url = 'https://leak-lookup.com/api/hash'

    """Executes list checks against LL API"""
    if str(os.path.exists(flist)) != 'True':
        print('[ERROR: List does not exist]')
    else:
        num=0
        pass_list = num_func(num)
        m = 0
        for j in pass_list:
            print('\nRunning [' + str(m) + ']')
            pyld = {'key' : ll_api, 'query' : j}
            chk = 'RATE'
            while chk == 'RATE':
                r = requests.post(ll_url, data=pyld).text
                print(str(r))
                chk = r.split(',')
                chk = str(chk[1])
                chk = chk[11:]
                chk = chk[:4]
                # print('chk=' + chk)
                if chk == 'RATE':
                    print('[WARNING: Rate limit detected.]')
                    for t in range(30, 0, -1):
                        print(f'Waiting {t} seconds...', end='\r', flush=True)
                        time.sleep(1)
            m += 1


def dhr_func():
    dh_url = 'https://api.dehashed.com/v2/search-password'

    """Executes list checks against DH API"""
    if str(os.path.exists(flist)) != 'True':
        print('[ERROR: List does not exist]')
    else:
        num=0
        pass_list = num_func(num)
        m = 0
        for j in pass_list:
            print('\nRunning [' + str(m) + ']')
            r = requests.post(dh_url, json = {"sha256_hashed_password" : j},
                    headers = {"Content-Type": "application/json", "DeHashed-Api-Key": dh_api}).text
            print(str(r))
            m += 1


def help_func():
    """Displays Main Help Menu"""
    print(' ')
    print('Menu Options:')
    print('  add      Adds passwd to list')
    print('  del      Deletes list')
    print('  db       Change db query')
    print('  h        Displays help menu')
    print('  import   Import list from sha')
    print('  q        Quit program')
    print('  num      Displays number of entries in list')
    print('  run      Runs program')
    print(' ')


def menu_func():
    """Runs Menu-based Interface"""
    cin = input('pwnchk>> ')
    while cin != 'q':
        match cin:
            case 'add':
                add_func()
            case 'del':
                del_func()
            case 'num':
                num = 1
                num_func(num)
            case 'run':
                run_func()
            case 'h':
                help_func()
            case 'import':
                import_func()
            case 'db':
                db_func()
            case _:
                print('Invalid command. Enter \'h\' to display help menu.')
        cin = input('pwnchk>> ')


def ver_func ():
    """Displays Code Version"""
    print('[pwnchk-' + v + ']')


def db_func():
    """Sets DB type"""
    global db_type
    print('Which db to query?')
    print('  0 - HaveIBeenPwned (default)')
    print('  1 - Leak Lookup')
    print('  2 - DeHashed')
    db_type = input('=> ')
    if db_type != '1' and db_type != '2':
        db_type = 0
    db_type = int(db_type)
    if db_type == 1:
        print('[DB: Leak Lookup.]')
    elif db_type == 2:
        print('[DB: DeHashed.]')
    else:
        print('[DB: HaveIBeenPwned.]')


def main():
    """Main Function"""
    global db_type
    ver_func()
    db_func()
    menu_func()

    if str(os.path.isfile(flist)) == 'True':
        print('[WARNING: File detected.]')


if __name__ == '__main__':
    main()

#!/usr/bin/python

import argparse
import getpass

WEAK_PSW_STRENGTH = 'weak'
MEDIUM_PSW_STRENGTH = 'medium'
STRONG_PSW_STRENGH = 'strong'

PSWM_FILE = '/home/sheny3/.pswm'
PSWM_FILE_TEMP = '/home/sheny3/.pswm.tmp'

class NoPasswordRecordsException(Exception):
    pass

class PSWMNotInitializedException(Exception):
    pass

class AuthorizationCheckFailedException(Exception):
    pass

class BasicAction(object):
    PSWM_FILE = '/home/sheny3/.pswm'
    PSWM_FILE_TEMP = '/home/sheny3/.pswm.tmp'

    def act(self, args):
        import os

        if os.path.exists(self.PSWM_FILE):
            hashed_one_pass = self.__authorize()
            self._act_if_inited(one_pass, args)
        else:
            self._act_if_not_inited(args)

    def _act_if_not_inited(self, args):
        raise PSWMNotInitializedException('PSWM is not initialized')

    def _act_if_inited(self, one_pass, args):
        pass

    def _get_new_password_with_double_check(self):
        first_input = 'first_input'
        secound_input = 'second_input'
        while first_input != secound_input:
            first_input = getpass.getpass('Please enter new password:')
            second_input = getpass.getpass('New password again:')
        return first_input

    def __get_one_password_hash(self):
        from Crypto.Hash import MD5

        password = getpass.getpass('One password:')
        md5_hash = MD5.new()
        md5_hash.update(password)
        return md5_hash.digest()

    def __authorize(self):
        password_hash = ''
        with open(self.PSWM_FILE, 'r') as pswm_file:
            stored_password_hash = pswm_file.readline().strip()
            if self.__get_one_password_hash() \
                    != stored_password_hash.decode('hex'):
                raise AuthorizationCheckFailedException(
                    'Authorization check failed')
            password_hash = stored_password_hash.decode('hex')
        return password_hash

class PSWMInitAction(BasicAction):
    def _act_if_not_inited(self, args):
        pass

    def _act_if_inited(self, one_pass, args):
        pass

    def __init_pswm(self, args):
        pass

def parse_arguments():
    arg_parser = argparse.ArgumentParser()
    
    # decide which action to do
    action_subparsers = arg_parser.add_subparsers(title='pswm actions')

    generate_action_parser = action_subparsers.add_parser('generate')
    generate_action_parser.add_argument(
        '-l', '--length', type=int, default=16,
        help='set the password length')
    generate_action_parser.add_argument(
        '-s', '--strength',
        choices=[
            WEAK_PSW_STRENGTH, 
            MEDIUM_PSW_STRENGTH, 
            STRONG_PSW_STRENGH,
            ],
        default=STRONG_PSW_STRENGH,
        help='set the password strength')
    generate_action_parser.add_argument(
        '-a', '--account', default='me',
        help='account name')
    generate_action_parser.add_argument(
        '-d', '--domain', required=True,
        help='domain name of the account')
    generate_action_parser.set_defaults(func=generate_password_action)

    get_action_parser = action_subparsers.add_parser('getpsw')
    get_action_parser.add_argument(
        '-a', '--account', default='me',
        help='account name')
    get_action_parser.add_argument(
        '-d', '--domain', required=True,
        help='domain name of the account')
    get_action_parser.set_defaults(func=get_password_action)

    setpsw_action_parser = action_subparsers.add_parser('setpsw')
    setpsw_action_parser.add_argument(
        '-a', '--account', default='me',
        help='account name')
    setpsw_action_parser.add_argument(
        '-d', '--domain', required=True,
        help='domain name of the account')
    setpsw_action_parser.set_defaults(func=set_password_action)

    return arg_parser.parse_args()

def generate_password(psw_strength, psw_length):
    import string
    import random
    import itertools

    psw = list()

    if psw_strength == WEAK_PSW_STRENGTH:
        char_sets = [string.ascii_lowercase, string.digits]
    elif psw_strength == MEDIUM_PSW_STRENGTH:
        char_sets = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    else:
        char_sets = [string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation]

    for char_set in char_sets:
        psw.append(char_set[random.randint(0, len(char_set) - 1)])

    all_char_set = list(itertools.chain.from_iterable(char_sets))
    for i in range(psw_length - len(char_sets)):
        psw.append(all_char_set[random.randint(0, len(all_char_set) - 1)])

    random.shuffle(psw)

    return ''.join(psw)

def update_content_in_file(account_hash, psw_cipher_text):
    import shutil
    with open(PSWM_FILE, 'r') as old_file, open(PSWM_FILE_TEMP, 'w') as new_file:
        for line in old_file:
            if not line.startswith(account_hash.encode('hex')):
                new_file.write(line.strip() + '\n')
        new_file.write(account_hash.encode('hex') + psw_cipher_text.encode('hex') + '\n')
    shutil.copyfile(PSWM_FILE_TEMP, PSWM_FILE)

def get_password_record_by_account(account_hash):
    pswm_file = open(PSWM_FILE, 'r')
    pswm_file.readline()
    for line in pswm_file:
        if line[:64] == account_hash.encode('hex'):
            pswm_file.close()
            return line.strip()[64:].decode('hex')
    pswm_file.close()
    raise NoPasswordRecordsException('No password for such account')

def generate_account(account_name, account_domain):
    return account_name + '@' + account_domain

def generate_account_hash(account_name, account_domain):
    from Crypto.Hash import SHA256

    account_hash = SHA256.new()
    account_hash.update(generate_account(account_name, account_domain))
    return account_hash.digest()

def persist_psw(account_name, account_domain, psw, one_password):
    from Crypto.Cipher import AES

    BS = AES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    update_content_in_file(
        generate_account_hash(account_name, account_domain),
        AES.new(one_password).encrypt(pad(psw)),
        )

def generate_password_action(args, one_password):
    psw = generate_password(args.strength, args.length)
    persist_psw(args.account, args.domain, psw, one_password)
    print psw

def get_password_action(args, one_password):
    from Crypto.Cipher import AES

    BS = AES.block_size
    unpad = lambda s: s[0:-ord(s[-1])]
    psw_cipher = AES.new(one_password)

    try:
        print unpad(psw_cipher.decrypt(
            get_password_record_by_account(
                generate_account_hash(args.account, args.domain))))
    except NoPasswordRecordsException, e:
        print 'No password record for account %s' % generate_account(args.account, args.domain)

def set_password_action(args, one_password):
    first_input = 'first'
    second_input = 'second'
    while first_input != second_input:
        first_input = getpass.getpass('New Password for %s:' % generate_account(args.account, args.domain))
        second_input = getpass.getpass('Password Again:')
    persist_psw(args.account, args.domain, first_input, one_password)

def main():
    from Crypto.Hash import MD5

    args = parse_arguments()
    one_password = getpass.getpass('One Password:')
    password_hash = MD5.new()
    password_hash.update(one_password)
    args.func(args, password_hash.digest())

if '__main__' == __name__:
    main()

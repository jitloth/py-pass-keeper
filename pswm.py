#!/usr/bin/python

import argparse
import getpass

WEAK_PSW_STRENGTH = 'weak'
MEDIUM_PSW_STRENGTH = 'medium'
STRONG_PSW_STRENGH = 'strong'

PSWM_FILE = '/home/sheny3/.pswm'

def parse_arguments():
    arg_parser = argparse.ArgumentParser()
    
    # decide which action to do
    action_subparsers = arg_parser.add_subparsers(title='pswm actions')

    generate_action_parser = action_subparsers.add_parser('generate')
    generate_action_parser.add_argument(
        '-l', '--length', type=int, default=16,
        help='set the password length',
        )
    generate_action_parser.add_argument(
        '-s', '--strength',
        choices=[
            WEAK_PSW_STRENGTH, 
            MEDIUM_PSW_STRENGTH, 
            STRONG_PSW_STRENGH,
            ],
        default=STRONG_PSW_STRENGH,
        help='set the password strength',
        )
    generate_action_parser.add_argument(
        '-a', '--account', default='me',
        help='account name',
        )
    generate_action_parser.add_argument(
        '-d', '--domain', required=True,
        help='domain name of the account',
        )
    generate_action_parser.set_defaults(func=generate_password_action)

    get_action_parser = action_subparsers.add_parser('get')
    get_action_parser.add_argument(
        '-a', '--account', default='me',
        help='account name',
        )
    get_action_parser.add_argument(
        '-d', '--domain', required=True,
        help='domain name of the account',
        )
    get_action_parser.set_defaults(func=get_password_action)

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
    pswm_file = open(PSWM_FILE, 'a')
    pswm_file.write(account_hash.encode('hex') + psw_cipher_text.encode('hex') + '\n')
    pswm_file.close()

def get_password_record_by_account(account_hash):
    pswm_file = open(PSWM_FILE, 'r')
    for line in pswm_file:
        if line[:64] == account_hash.encode('hex'):
            pswm_file.close()
            return line[64:-1].decode('hex')
    pswm_file.close()
    raise Exception('No password for such account')

def generate_account_hash(account_name, account_domain):
    from Crypto.Hash import SHA256

    account_hash = SHA256.new()
    account_hash.update(account_name + '@' + account_domain)
    return account_hash.digest()

def generate_password_action(args, one_password):
    from Crypto.Cipher import AES

    psw = generate_password(args.strength, args.length)
    BS = AES.block_size
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    update_content_in_file(
        generate_account_hash(args.account, args.domain),
        AES.new(one_password).encrypt(pad(psw)),
        )

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
    except Exception, e:
        print 'No password record for account %s' % (args.account + '@' + args.domain)

def main():
    from Crypto.Hash import MD5

    args = parse_arguments()
    one_password = getpass.getpass()
    password_hash = MD5.new()
    password_hash.update(one_password)
    args.func(args, password_hash.digest())

if '__main__' == __name__:
    main()

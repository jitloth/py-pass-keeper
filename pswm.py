#!/usr/bin/python

import argparse
import getpass
import os

WEAK_PSW_STRENGTH = 'weak'
MEDIUM_PSW_STRENGTH = 'medium'
STRONG_PSW_STRENGH = 'strong'

PSWM_FILE = os.path.expanduser('~') + '/.pswm'
PSWM_FILE_TEMP = PSWM_FILE + '.tmp'

class NoPasswordRecordsException(Exception):
    pass

class PSWMNotInitializedException(Exception):
    pass

class AuthorizationCheckFailedException(Exception):
    pass

class PSWMPasswordPersistence(object):
    from Crypto.Cipher import AES
    from Crypto.Hash import MD5

    BS = AES.block_size
    PAD = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
    UNPAD = lambda s: s[0:-ord(s[-1])]

    def __init__(self, file_path, raw_key):
        self.pswm_file = file_path
        md5_hash = PSWMPasswordPersistence.MD5.new()
        md5_hash.update(raw_key)
        self.cipher_key = md5_hash.digest()

    def store_password(account, password):
        import shutil

        with open(self.pswm_file, 'r') as old_file, \
                open(self.pswm_file + '.tmp', 'w') as new_file:
            aes_cipher = PSWMPasswordPersistence.AES.new(self.key)
            encrypted_account = aes_cipher.encrypt(
                PSWMPasswordPersistence.PAD(account)).encode('hex')
            encrypted_psw = aes_cipher.encrypt(
                PSWMPasswordPersistence.PAD(password)).encode('hex')

            new_file.write(old_file.readline().strip() + '\n')
            for line in old_file:
                if not line.startswith(encrypted_account):
                    new_file.write(line.strip() + '\n')
            new_file.write(encrypted_account + ':' + encrypted_psw + '\n')
        
        shutil.copyfile(self.pswm_file + '.tmp', self.pswm_file)

    def get_password(account, password):
        pass

class BasicAction(object):
    def act(self, args):
        import os

        self.act_args = args

        if os.path.exists(self.act_args.file_path):
            self.one_pass = self.__authorize()
            self._act_if_inited()
        else:
            self._act_if_not_inited()

    def _act_if_not_inited(self):
        raise PSWMNotInitializedException('PSWM is not initialized')

    def _act_if_inited(self):
        pass

    def _get_new_password_with_double_check(self):
        first_input = 'first_input'
        secound_input = 'second_input'
        while first_input != secound_input:
            first_input = getpass.getpass('Please enter new password:')
            second_input = getpass.getpass('New password again:')
        return first_input

    def _get_account(self):
        return self.act_args.account + '@' + self.act_args.domain

    def __authorize(self):
        one_pass = getpass.getpass('One password:')
        with open(self.act_args.file_path, 'r') as pswm_file:
            from Crypto.Hash import SHA256
            sha256_hash = SHA256.new()
            sha256_hash.update(one_pass)
            if pswm_file.readline().strip().decode('hex') \
                    != sha256_hash.digest():
                raise AuthorizationCheckFailedException(
                    'Authorization check failed')
        return one_pass

class PSWMInitAction(BasicAction):
    def _act_if_not_inited(self):
        self.__init_pswm()

    def _act_if_inited(self):
        pass

    def __init_pswm(self):
        from Crypto.Hash import SHA256

        with open(self.act_args.file_path, 'w') as pswm_file:
            one_pass = self._get_new_password_with_double_check()
            sha256_hash = SHA256.new()
            sha256_hash.update(one_pass)
            pswm_file.write(sha256_hash.hexdigest() + '\n')

class GenerateAction(BasicAction):
    WEAK_PSW_STRENGTH = 'weak'
    MEDIUM_PSW_STRENGTH = 'medium'
    STRONG_PSW_STRENGH = 'strong'

    def _act_if_inited(self):
        password = self.__generate_password()
        PSWMPasswordPersistence(
            self.act_args.file_path,
            self.one_pass).store_password(self._get_account, password)
        print password

    def __generate_password(self):
        import string
        import random
        import itertools

        psw = list()

        if self.act_args.strength == GenerateAction.WEAK_PSW_STRENGTH:
            char_sets = [
                string.ascii_lowercase,
                string.digits,
                ]
        elif self.act_args.strength == GenerateAction.MEDIUM_PSW_STRENGTH:
            char_sets = [
                string.ascii_lowercase,
                string.ascii_uppercase,
                string.digits,
                ]
        else:
            char_sets = [
                string.ascii_lowercase,
                string.ascii_uppercase,
                string.digits,
                string.punctuation,
                ]

        for char_set in char_sets:
            psw.append(char_set[random.int(0, len(char_set) - 1)])

        all_char_set = list(itertools.chain.from_iterable(char_sets))
        for i in range(self.act_args.length - len(char_sets)):
            psw.append(all_char_set[random.randint(0, len(all_char_set) - 1)])

        random.shuffle(psw)

        return ''.join(psw)

def parse_arguments():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument(
        '-f', '--file_path',
        default=os.path.abspath(os.path.expanduser('~') + '/.pswm'),
        help='set pswm file path [default: %(default)s]')
    
    # decide which action to do
    action_subparsers = arg_parser.add_subparsers(title='pswm actions')

    generate_action_parser = action_subparsers.add_parser('generate')
    generate_action_parser.add_argument(
        '-l', '--length', type=int, default=16,
        help='set the password length [default: %(default)s]')
    generate_action_parser.add_argument(
        '-s', '--strength',
        choices=[
            WEAK_PSW_STRENGTH, 
            MEDIUM_PSW_STRENGTH, 
            STRONG_PSW_STRENGH,
            ],
        default=STRONG_PSW_STRENGH,
        help='set the password strength [default: %(default)s]')
    generate_action_parser.add_argument(
        '-a', '--account', default='me',
        help='account name [default: %(default)s]')
    generate_action_parser.add_argument(
        '-d', '--domain', required=True,
        help='domain name of the account')
    generate_action_parser.set_defaults(func=generate_password_action)

    get_action_parser = action_subparsers.add_parser('getpsw')
    get_action_parser.add_argument(
        '-a', '--account', default='me',
        help='account name [default: %(default)s]')
    get_action_parser.add_argument(
        '-d', '--domain', required=True,
        help='domain name of the account')
    get_action_parser.set_defaults(func=get_password_action)

    setpsw_action_parser = action_subparsers.add_parser('setpsw')
    setpsw_action_parser.add_argument(
        '-a', '--account', default='me',
        help='account name [default: %(default)s]')
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

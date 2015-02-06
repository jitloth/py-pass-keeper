#!/usr/bin/python

import argparse
import getpass
import os

class NoPasswordRecordsException(Exception):
    pass

class PSWMNotInitializedException(Exception):
    pass

class AuthorizationCheckFailedException(Exception):
    pass

class InvalidInputValueException(Exception):
    pass

class PSWMAlreadyInitializedException(Exception):
    pass

class PSWMPasswordPersistence(object):
    def __init__(self, file_path, raw_key):
        from Crypto.Hash import MD5

        self.pswm_file = file_path
        md5_hash = MD5.new()
        md5_hash.update(raw_key)
        self.cipher_key = md5_hash.digest()

    def store_password(self, account, password):
        import shutil
        from Crypto.Cipher import AES

        with open(self.pswm_file, 'r') as old_file, \
                open(self.pswm_file + '.tmp', 'w') as new_file:
            aes_cipher = AES.new(self.cipher_key)
            encrypted_account = aes_cipher.encrypt(
                self.__pad(account)).encode('hex')
            encrypted_psw = aes_cipher.encrypt(
                self.__pad(password)).encode('hex')

            new_file.write(old_file.readline().strip() + '\n')
            for line in old_file:
                if not line.startswith(encrypted_account):
                    new_file.write(line.strip() + '\n')
            new_file.write(encrypted_account + ':' + encrypted_psw + '\n')

        shutil.copyfile(self.pswm_file + '.tmp', self.pswm_file)

    def get_password(self, account):
        from Crypto.Cipher import AES

        with open(self.pswm_file, 'r') as pswm_file:
            aes_cipher = AES.new(self.cipher_key)
            encrypted_account = aes_cipher.encrypt(
                self.__pad(account)).encode('hex')
            pswm_file.readline()
            for line in pswm_file:
                if line.startswith(encrypted_account):
                    return self.__unpad(aes_cipher.decrypt(
                        line.strip().split(':')[1].decode('hex')))
        return None

    def get_all_accounts(self):
        from Crypto.Cipher import AES

        account_list = list()
        with open(self.pswm_file, 'r') as pswm_file:
            pswm_file.readline()
            aes_cipher = AES.new(self.cipher_key)
            for line in pswm_file:
                account_list.append(self.__unpad(aes_cipher.decrypt(
                    line.strip().split(':')[0].decode('hex'))))
            pass

        return account_list

    def __pad(self, s):
        from Crypto.Cipher import AES

        BS = AES.block_size
        return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

    def __unpad(self, s):
        return s[0:-ord(s[-1])]

class BasicAction(object):
    def act(self, args):
        import os

        self.act_args = args

        self._check_args()

        if os.path.exists(self.act_args.file_path):
            self.one_pass = self.__authorize()
            self._act_if_inited()
        else:
            self._act_if_not_inited()

    def _act_if_not_inited(self):
        raise PSWMNotInitializedException('PSWM is not initialized')

    def _act_if_inited(self):
        pass

    def _check_args(self):
        # TODO: check input file_path
        pass

    def _get_new_password_with_double_check(self):
        first_input = 'first_input'
        secound_input = 'second_input'
        while first_input != secound_input:
            first_input = getpass.getpass('Please enter new password:')
            secound_input = getpass.getpass('New password again:')
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
        if self.act_args.force_init:
            self.__init_pswm()
        else:
            raise PSWMAlreadyInitializedException(
                'PSWM has already been initialized')

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
    STRONG_PSW_STRENGTH = 'strong'

    def _act_if_inited(self):
        password = self.__generate_password()
        PSWMPasswordPersistence(
            self.act_args.file_path,
            self.one_pass).store_password(self._get_account(), password)
        print password

    def _check_args(self):
        # TODO: call super
        if self.act_args.length < 6:
            raise InvalidInputValueException('Input length %s is invalid' %
                self.act_args.length)

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
            psw.append(char_set[random.randint(0, len(char_set) - 1)])

        all_char_set = list(itertools.chain.from_iterable(char_sets))
        for i in range(self.act_args.length - len(char_sets)):
            psw.append(all_char_set[random.randint(0, len(all_char_set) - 1)])

        random.shuffle(psw)

        return ''.join(psw)

class GetPswAction(BasicAction):
    def _act_if_inited(self):
        password = PSWMPasswordPersistence(
            self.act_args.file_path,
            self.one_pass).get_password(self._get_account())
        if password is None:
            raise NoPasswordRecordsException(
                'Has no password record for account %s' % self._get_account())
        print password

class SetPswAction(BasicAction):
    def _act_if_inited(self):
        password = self._get_new_password_with_double_check()
        PSWMPasswordPersistence(
            self.act_args.file_path,
            self.one_pass).store_password(self._get_account(), password)

class ListPswRecordAction(BasicAction):
    def _act_if_inited(self):
        for account in PSWMPasswordPersistence(
                self.act_args.file_path,
                self.one_pass).get_all_accounts():
            print account

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
            GenerateAction.WEAK_PSW_STRENGTH,
            GenerateAction.MEDIUM_PSW_STRENGTH,
            GenerateAction.STRONG_PSW_STRENGTH,
            ],
        default=GenerateAction.STRONG_PSW_STRENGTH,
        help='set the password strength [default: %(default)s]')
    generate_action_parser.add_argument(
        '-a', '--account', default='me',
        help='account name [default: %(default)s]')
    generate_action_parser.add_argument(
        '-d', '--domain', required=True,
        help='domain name of the account')
    generate_action_parser.set_defaults(act_obj=GenerateAction())

    get_action_parser = action_subparsers.add_parser('getpsw')
    get_action_parser.add_argument(
        '-a', '--account', default='me',
        help='account name [default: %(default)s]')
    get_action_parser.add_argument(
        '-d', '--domain', required=True,
        help='domain name of the account')
    get_action_parser.set_defaults(act_obj=GetPswAction())

    setpsw_action_parser = action_subparsers.add_parser('setpsw')
    setpsw_action_parser.add_argument(
        '-a', '--account', default='me',
        help='account name [default: %(default)s]')
    setpsw_action_parser.add_argument(
        '-d', '--domain', required=True,
        help='domain name of the account')
    setpsw_action_parser.set_defaults(act_obj=SetPswAction())

    init_action_parser = action_subparsers.add_parser('init')
    init_action_parser.add_argument(
        '--force-init', action='store_true',
        help='force init if pswm was already initialized, need authorization')
    init_action_parser.set_defaults(act_obj=PSWMInitAction())

    list_action_parser = action_subparsers.add_parser('list')
    list_action_parser.set_defaults(act_obj=ListPswRecordAction())

    return arg_parser.parse_args()

def main():
    args = parse_arguments()
    args.act_obj.act(args)

if '__main__' == __name__:
    main()

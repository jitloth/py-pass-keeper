#!/usr/bin/python

from argparse import ArgumentParser
from getpass import getpass
from os import path


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
        import time

        with open(self.pswm_file, 'r') as old_file, \
                open(self.pswm_file + '.tmp', 'w') as new_file:
            aes_cipher = AES.new(self.cipher_key)
            encrypted_account = aes_cipher.encrypt(
                self.__pad(account)).encode('hex')
            encrypted_psw = aes_cipher.encrypt(
                self.__pad(password + '|' + str(time.time()))
                ).encode('hex')

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
                        line.strip().split(':')[1].decode('hex')
                        )).split('|')[0]
        return None

    def get_all_accounts(self, sort_key=None):
        from Crypto.Cipher import AES

        account_list = list()
        with open(self.pswm_file, 'r') as pswm_file:
            pswm_file.readline()
            aes_cipher = AES.new(self.cipher_key)
            for line in pswm_file:
                account_list.append(self.__unpad(aes_cipher.decrypt(
                    line.strip().split(':')[0].decode('hex'))))
            pass

        if sort_key is not None:
            account_list = sorted(account_list, key=sort_key)

        return account_list

    @staticmethod
    def __pad(s):
        from Crypto.Cipher import AES

        bs = AES.block_size
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    @staticmethod
    def __unpad(s):
        return s[0:-ord(s[-1])]


class BasicAction(object):
    def __init__(self):
        self.act_args = None
        self.one_pass = None

    def act(self, args):
        from os import path

        self.act_args = args

        self._check_args()

        if path.exists(self.act_args.file_path):
            self.one_pass = self.__authorize()
            self._act_if_inited()
        else:
            self._act_if_not_inited()

    def _act_if_not_inited(self):
        raise PSWMNotInitializedException('PSWM is not initialized')

    def _act_if_inited(self):
        pass

    def _check_args(self):
        pass

    def _get_account(self):
        return self.act_args.account + '@' + self.act_args.domain

    def __authorize(self):
        one_pass = getpass('One password:')
        with open(self.act_args.file_path, 'r') as pswm_file:
            from Crypto.Hash import SHA256

            sha256_hash = SHA256.new()
            sha256_hash.update(one_pass)
            if pswm_file.readline().strip().decode('hex') \
                    != sha256_hash.digest():
                raise AuthorizationCheckFailedException(
                    'Authorization check failed')
        return one_pass


def get_double_checked_pass():
    first_input = 'first_input'
    second_input = 'second_input'
    while first_input != second_input:
        first_input = getpass('Please enter new password:')
        second_input = getpass('New password again:')
    return first_input


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
            one_pass = get_double_checked_pass()
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
        password = get_double_checked_pass()
        PSWMPasswordPersistence(
            self.act_args.file_path,
            self.one_pass).store_password(self._get_account(), password)


class ListPswRecordAction(BasicAction):
    LIST_RESULT_SORT = {
        'time': None,
        'domain_alpha': (lambda x: x.split('@')[-1] + x.split('@')[0]),
        'account_alpha': (lambda x: x.split('@')[0] + x.split('@')[-1]),
        }

    DEFAULT_SORT = 'time'

    def _act_if_inited(self):
        psw_persistence = PSWMPasswordPersistence(
            self.act_args.file_path,
            self.one_pass)

        for i, account in enumerate(psw_persistence.get_all_accounts(
                ListPswRecordAction.LIST_RESULT_SORT[self.act_args.sort])):
            print "%3d. %s" % (i + 1, account)


def parse_arguments():
    arg_parser = ArgumentParser()

    arg_parser.add_argument(
        '-f', '--file_path',
        default=path.abspath(path.expanduser('~') + '/.pswm'),
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
    list_action_parser.add_argument(
        '--sort',
        choices=list(ListPswRecordAction.LIST_RESULT_SORT),
        default=ListPswRecordAction.DEFAULT_SORT,
        help='define the output sequence of list result [default: %(default)s]')
    list_action_parser.set_defaults(act_obj=ListPswRecordAction())

    return arg_parser.parse_args()


def main():
    args = parse_arguments()
    args.act_obj.act(args)


if '__main__' == __name__:
    main()

#!/usr/bin/python

import argparse
import string
import random
import itertools

WEAK_PSW_STRENGTH = 'weak'
MEDIUM_PSW_STRENGTH = 'medium'
STRONG_PSW_STRENGH = 'strong'

def parse_arguments():
    arg_parser = argparse.ArgumentParser()
    
    # decide which action to do
    action_subparsers = arg_parser.add_subparsers(title='pswm actions')

    generate_action_parser = action_subparsers.add_parser('generate')
    generate_action_parser.add_argument('account')
    generate_action_parser.add_argument(
        '-l', '--length', type=int, default=8,
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
    generate_action_parser.set_defaults(func=generate_password_action)

    get_action_parser = action_subparsers.add_parser('get')
    get_action_parser.add_argument('account')

    return arg_parser.parse_args()

def generate_password(psw_strength, psw_length):
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

def format_account(input_account_string):
    account_info = input_account_string.split('@')
    account_name = 'me'
    if len(account_info) > 1 and account_info[0] != '':
        account_name = account_info[0]
    return account_name + '@' + account_info[-1]

def generate_password_action(args):
    psw = generate_password(args.strength, args.length)
    account = format_account(args.account)
    print account, psw

def main():
    args = parse_arguments()
    args.func(args)

if '__main__' == __name__:
    main()

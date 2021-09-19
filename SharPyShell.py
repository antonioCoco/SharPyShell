#!/usr/bin/env python3

from core.Generate import Generate
from core.SharPyShellPrompt import SharPyShellPrompt
from core import config
import argparse


example_text_main = '''
examples:
    python SharPyShell.py generate -p 'somepassword'
    python SharPyShell.py interact -u 'http://target.url/sharpyshell.aspx' -p 'somepassword'
'''


def create_generate_parser(subparsers):
    generate_parser = subparsers.add_parser(
        'generate', formatter_class=argparse.RawTextHelpFormatter,
        usage='SharPyShell.py generate -p password -e encryption -o obfuscator [--output] [--endian-type]',
        help='Generate the obfuscated webshell agent',
    )
    generate_parser._action_groups.pop()
    required_generate_parser = generate_parser.add_argument_group('required arguments')
    optional_generate_parser = generate_parser.add_argument_group('optional arguments')
    required_generate_parser.add_argument(
        '-p',
        '--password',
        help='\tThe password to use as a shared key for encrypting the channel',
        required=True,
        metavar='\b'
    )
    required_generate_parser.add_argument(
        '-e',
        '--encryption',
        help='\tThe encryption scheme to use for encrypting the communication channel'
             '\nAllowed values: \'xor\', \'aes128\', \'aes256\''
             '\nDefault \'xor\'',
        choices=['xor', 'aes128', 'aes256'],
        default='xor',
        metavar='\b'
    )
    required_generate_parser.add_argument(
        '-o',
        '--obfuscator',
        help='\tThe obfuscator to use for the webshell agent'
             '\nAllowed values: \'raw\', \'encrypted_dll\', \'encrypted_dll_ulong_compression\''
             '\nDefault \'encrypted_dll\'',
        choices=['raw', 'encrypted_dll', 'encrypted_dll_ulong_compression'],
        default='encrypted_dll',
        metavar='\b'
    )
    optional_generate_parser.add_argument(
        '--output',
        help='\tThe output path where to generate the webshell agent',
        metavar='\b'
    )
    optional_generate_parser.add_argument(
        '--endian-type',
        help='\tThe Endianess type for ulong representation'
             '\nSet if your machine and the target server have different CPU Endianess type'
             '\nThis is valid only for \'encrypted_dll_ulong_compression\' obfuscator'
             '\nAllowed values: \'default\', \'little\', \'big\''
             '\nDefault \'default\'',
        choices=['default', 'little', 'big'],
        default='default',
        metavar='\b'
    )
    generate_parser.set_defaults(mode='generate')


def create_interact_parser(subparsers):
    interact_parser = subparsers.add_parser(
        'interact',  formatter_class=argparse.RawTextHelpFormatter,
        usage='SharPyShell.py interact -u URL -p password -e encryption [--default-shell] [--user-agent] [--cookies] [--custom-header] [--insecure] [--proxy]',
        help='Run terminal and interact with the remote agent'
    )
    interact_parser._action_groups.pop()
    required_interact_parser = interact_parser.add_argument_group('required arguments')
    optional_interact_parser = interact_parser.add_argument_group('optional arguments')
    required_interact_parser.add_argument(
        '-u',
        '--url',
        help='\tThe remote agent url',
        required=True,
        metavar='\b'
    )
    required_interact_parser.add_argument(
        '-p',
        '--password',
        help='\tThe password to use as a shared key for encrypting the channel',
        required=True,
        metavar='\b'
    )
    required_interact_parser.add_argument(
        '-e',
        '--encryption',
        help='\tThe encryption scheme to use for encrypting the communication channel'
             '\nAllowed values: \'xor\', \'aes128\', \'aes256\''
             '\nDefault \'xor\'',
        choices=['xor', 'aes128', 'aes256'],
        default='xor',
        metavar='\b'
    )
    optional_interact_parser.add_argument(
        '--default-shell',
        help='\tThe default shell to use for the terminal'
             '\nAllowed values: \'exec_cmd\', \'exec_ps\''
             '\nDefault \'exec_cmd\'',
        choices=['exec_cmd', 'exec_ps'],
        default='exec_cmd',
        metavar='\b'
    )
    optional_interact_parser.add_argument(
        '--user-agent',
        help='\tThe user agent to use for the requests',
        default='default',
        metavar='\b'
    )
    optional_interact_parser.add_argument(
        '--cookies',
        help='\tCookies value to send within the requests',
        default=False,
        metavar='\b'
    )
    optional_interact_parser.add_argument(
        '--custom-header',
        help='\tCustom header to send within the requests',
        default=False,
        metavar='\b'
    )
    optional_interact_parser.add_argument(
        '--insecure',
        help='\tIf set to true, it skips the check for a valid ssl certificate',
        default='false',
        metavar='\b'
    )
    optional_interact_parser.add_argument(
        '--proxy',
        help='\tHttp, https or socks proxy to use within requests',
        default=False,
        metavar='\b'
    )
    interact_parser.set_defaults(mode='interact')


if __name__ == '__main__':
    print (config.banner)
    parser = argparse.ArgumentParser(prog='SharPyShell', formatter_class=argparse.RawTextHelpFormatter,
                                     epilog=example_text_main)
    parser.add_argument('--version', action='version', version=config.header)
    subparsers = parser.add_subparsers()
    create_generate_parser(subparsers)
    create_interact_parser(subparsers)
    args = parser.parse_args()

    if args.__contains__('mode'):
        if args.mode == 'generate':
            generate_obj = Generate(args.password, args.encryption, args.obfuscator, args.endian_type, args.output)
            generate_obj.generate()

        if args.mode == 'interact':
            prompt = SharPyShellPrompt(args.password, args.encryption, args.default_shell, args.url,
                                       args.user_agent, args.cookies, args.custom_header, args.insecure, args.proxy)
            prompt.cmdloop('\n')
    else:
        parser.print_help()

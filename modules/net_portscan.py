from core.Module import Module, ModuleException
from modules.invoke_ps_module import Invoke_ps_module
from modules.exec_cmd import Exec_cmd
from utils.random_string import random_generator
import traceback


class NetPortscanModuleException(ModuleException):
    pass


class Net_portscan(Module):
    _exception_class = NetPortscanModuleException
    short_help = "Run a port scan using regular sockets, based (pretty) loosely on nmap"
    complete_help = r"""
        This module run the Invoke-Portscan.ps1 script in order to perform a portscan on a host or network.
        
        Source Code: 
            https://github.com/EmpireProject/Empire/blob/master/data/module_source/situational_awareness/network/Invoke-Portscan.ps1                        
        
        Usage:
            #net_portscan hosts [ports] [custom_arguments]
        
        Positional arguments:
            hosts                   ip or hostnames to scan
                                    ranges can be used with "-" separator or CIDR notation
            ports                   ports to be scanned
                                    different ports can be specified using ',' separator
                                    ranges can be used with "-" separator
                                    Default: 'Top25'
            custom_arguments        custom arguments for ps1 module
                                    Default: ' -T 3 '
                                        
        Examples:
            Run default portscan on a subnet
                #net_portscan 192.168.1.0/24
            Run portscan on specific ports
                #net_portscan 192.168.1.0/24 '445'
            Run portscan on specific ports and with aggressive mode
                #net_portscan 192.168.1.0/24 '445' ' -T 5 '

    """

    __default_ports = 'default'
    __default_custom_arguments = ' -T 3 '
    __appended_code_ps_module = ';Invoke-Portscan -Hosts "%s" %s %s -oN %s'

    def __init__(self, password, channel_enc_mode, module_settings, request_object):
        Module.__init__(self, password, channel_enc_mode, module_settings, request_object)
        self.invoke_ps_module_object = Invoke_ps_module(password, channel_enc_mode, module_settings, request_object)
        self.exec_cmd_module_object = Exec_cmd(password, channel_enc_mode, module_settings, request_object)

    def __parse_run_args(self, args):
        if len(args) < 1:
            raise self._exception_class('#net_portscan: Not enough arguments. 1 Argument required.\n')
        args_parser = {k: v for k, v in enumerate(args)}
        hosts = args_parser.get(0)
        ports = args_parser.get(1, self.__default_ports)
        custom_arguments = args_parser.get(2, self.__default_custom_arguments)
        return hosts, ports, custom_arguments

    def __gen_appended_code(self, hosts, ports, custom_arguments, output_file):
        ports = '-TopPorts 25' if ports == 'default' else '-Ports "' + ports + '"'
        appended_code = self.__appended_code_ps_module % (hosts, ports, custom_arguments, output_file)
        return appended_code

    def run(self, args):
        try:
            hosts, ports, custom_arguments = self.__parse_run_args(args)
            output_file = self._module_settings['env_directory'] + '\\' + random_generator()
            appended_code = self.__gen_appended_code(hosts, ports, custom_arguments, output_file)
            self._parse_response(self.invoke_ps_module_object.run(['Invoke-Portscan.ps1', appended_code]))
            response = self.exec_cmd_module_object.run(['type ' + output_file + ' & del /f /q ' + output_file])
            parsed_response = self._parse_response(response)
        except ModuleException as module_exc:
            parsed_response = str(module_exc)
        except Exception:
            parsed_response = '{{{' + self._exception_class.__name__ + '}}}' + '{{{PythonError}}}\n' +\
                              str(traceback.format_exc())
        return parsed_response

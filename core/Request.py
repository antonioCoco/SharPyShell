from utils.Singleton import Singleton
from utils.Singleton import Singleton
import ssl
import urllib3
from urllib3.contrib.socks import SOCKSProxyManager


class Request(Singleton):

    __request_timeout = 180
    __allow_redirects = False
    __default_user_agent = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:62.0) Gecko/20100101 Firefox/62.0'

    def __parse_custom_header(self, custom_header):
        parsed_custom_header = custom_header.split(':')
        custom_header_key = parsed_custom_header[0].strip()
        custom_header_value = parsed_custom_header[1].strip()
        self.__headers[custom_header_key] = custom_header_value

    def __init__(self, url, user_agent, cookies_string=False, custom_header=False, insecure_ssl='false', proxy=False):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.__url = url
        self.__headers = dict()
        self.__headers['User-Agent'] = self.__default_user_agent if user_agent == 'default' else user_agent
        if cookies_string:
            self.__headers['Cookie'] = cookies_string
        if custom_header:
            self.__parse_custom_header(custom_header)
        self.__verify = 'CERT_REQUIRED' if insecure_ssl == 'false' else 'CERT_NONE'
        if proxy:
            proxy_type = proxy.split('://')[0]
            if proxy_type == 'http' or proxy_type == 'https':
                self.__request_obj = urllib3.ProxyManager(proxy, ssl_version=ssl.PROTOCOL_TLS_CLIENT,
                                                          timeout=self.__request_timeout, cert_reqs=self.__verify)
            else:
                self.__request_obj = SOCKSProxyManager(proxy, ssl_version=ssl.PROTOCOL_TLS_CLIENT,
                                                       timeout=self.__request_timeout, cert_reqs=self.__verify)
        else:
            self.__request_obj = urllib3.PoolManager(ssl_version=ssl.PROTOCOL_TLS_CLIENT, timeout=self.__request_timeout,
                                                     cert_reqs=self.__verify)
        # print (vars(self))

    def send_request(self, request):
        try:
            response_object = self.__request_obj.request('POST',
                                                         self.__url,
                                                         fields={'data': request},
                                                         redirect=self.__allow_redirects,
                                                         headers=self.__headers,
                                                         retries=False
                                                         )
        except KeyboardInterrupt:
            raise Exception('Keyboard interrupt issued')
        return response_object.status, response_object.headers, response_object.data

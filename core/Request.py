from utils.Singleton import Singleton
import requests


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
        self.__url = url
        self.__headers = dict()
        self.__headers['User-Agent'] = self.__default_user_agent if user_agent == 'default' else user_agent
        if cookies_string:
            self.__headers['Cookie'] = cookies_string
        if custom_header:
            self.__parse_custom_header(custom_header)
        self.__verify = True if insecure_ssl == 'false' else False
        if proxy:
            self.__proxies = dict()
            self.__proxies['http'] = proxy
            self.__proxies['https'] = proxy
        else:
            self.__proxies = False
        # print (vars(self))

    def send_request(self, request):
        try:
            response_object = requests.post(self.__url,
                                            data={'data': request},
                                            timeout=self.__request_timeout,
                                            allow_redirects=self.__allow_redirects,
                                            headers=self.__headers,
                                            verify=self.__verify,
                                            proxies=self.__proxies
                                            )
        except KeyboardInterrupt:
            raise Exception('Keyboard interrupt issued')
        return response_object.status_code, response_object.headers, response_object.text

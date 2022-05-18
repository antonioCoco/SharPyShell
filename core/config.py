import sys
import os

sharpyshell_version='1.3'

header = '#SharPyShell v' + sharpyshell_version + ' - @splinter_code'
banner = """


          ____    _  _              ____        ____  _          _ _ 
         / ___| _| || |_  __ _ _ __|  _ \ _   _/ ___|| |__   ___| | |
         \___ \|_  ..  _|/ _` | '__| |_) | | | \___ \| '_ \ / _ \ | |
          ___) |_      _| (_| | |  |  __/| |_| |___) | | | |  __/ | |
         |____/  |_||_|  \__,_|_|  |_|    \__, |____/|_| |_|\___|_|_|
                                          |___/                      
         %s        



    """ % header

sharpyshell_path=os.path.dirname(os.path.realpath(sys.argv[0])) + os.sep
sys.path.insert(0, sharpyshell_path)
modules_paths=sharpyshell_path + 'modules' + os.sep
output_path=sharpyshell_path + 'output' + os.sep

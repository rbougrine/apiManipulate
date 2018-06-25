from winappdbg import Debug, EventHandler, System, Process

from winappdbg.win32 import *
import kill

class MyEventHandler( EventHandler ):


    # Here we set which API calls we want to intercept.
    apiHooks = {

        # Hooks for the kernel32 library.
        'kernel32.dll' : [

            #  Function
            ( 'CreateFileA', 7),
            ( 'CreateFileW', 7),

        ],

        # Hooks for the advapi32 library.
        'advapi32.dll' : [

            #  Function
            ( 'RegCreateKeyExA', 9),
            ( 'RegCreateKeyExW', 9),

        ],

    }
    # Methods beginning with "pre_" are called when entering the API,

    def pre_CreateFileW( self, event, ra, lpFileName, dwDesiredAccess,
             dwShareMode, lpSecurityAttributes, dwCreationDisposition,
                                dwFlagsAndAttributes, hTemplateFile):
        self.lpFileName = lpFileName
        self.dwDesiredAccess = dwDesiredAccess
        self.dwShareMode = dwShareMode
        self.lpSecurityAttributes = lpSecurityAttributes
        self.dwCreationDisposition = dwCreationDisposition
        self.dwFlagsAndAttributes = dwFlagsAndAttributes
        self.hTemplateFile = hTemplateFile

        self.__print_opening_unicode(event, "file", lpFileName)
        process = event.get_process()
        import pdb; pdb.set_trace()
        process.inject_code('\xB0\x2B\x24\xDC\xC3')

    # Methods beginning with "post_" when returning from the API.

    def post_CreateFileW(self, event, retval):
        process = event.get_process()
        # process.suspend()
        processInfo = process.peek_string(self.dwShareMode, fUnicode=False)
        print("processInfo: %s" % processInfo)

        print(self.dwDesiredAccess)
        # process.resume()
        self.__print_success(event, retval)

    def __print_opening_unicode(self, event, tag, pointer):
        string = event.get_process().peek_string(pointer, fUnicode = True )
        tid    = event.get_tid()
        print  ("%d: Opening %s: %s" % (tid, tag, string))

    def __print_success(self, event, retval):
        tid = event.get_tid()
        if retval:
            print ("%d: Success: %x" % (tid, retval))
        else:
            print ("%d: Failed!" % tid)


def simple_debugger( argv ):

    # Instance a Debug object, passing it the MyEventHandler instance.
    with Debug( MyEventHandler(), bKillOnExit = True ) as debug:

        # Start a new process for debugging.
        debug.execv( argv )

        # Wait for the debugee to finish.
        debug.loop()


# When invoked from the command line,
# the first argument is an executable file,
# and the remaining arguments are passed to the newly created process.
if __name__ == "__main__":
    import sys
    simple_debugger( sys.argv[1:] )

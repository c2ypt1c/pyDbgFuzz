from pydbg import *
from pydbg.defines import *

# obtained from the paimei project: https://github.com/OpenRCE/paimei/blob/master/utils/crash_binning.py
from crash_binning import *

import threading
import subprocess
import time

gflags_path = "C:\\Program Files\\Windows Kits\\8.1\\Debuggers\\x86\\gflags.exe"
# or place gflags in current directory
#gflags_path = "gflags.exe"


class pydbg_fuzz:

    ################################################################################
    # @param opts: a struct/class object containing the fuzzing options:
    #       opts.exe
    #       opts.fuzzed_file
    #       opts.timeout
    ###
    def __init__(self, opts):
        #FIXME: create log directory if it doesn't exist
        self.opts = opts
        self.t = threading.Thread(target=self.fuzz)
        self.t.start()

        self.timer = threading.Timer(self.opts.timeout, self.kill_proc)
        self.timer.start()

        # wait until thread terminates
        self.t.join()
    
    ################################################################################
    # Terminates the current debugged process
    ###
    def kill_proc(self):
        self.timer.cancel()
        self.dbg.terminate_process()

    ################################################################################
    # Creates backup files when a crash occurs
    ###
    def create_backup(self, timestamp):
        #FIXME: create crash directory for each crash
        # and write backups into it
        fin = open(self.opts.fuzzed_file, 'rb')
        fout = open("%s%s_poc.bak" % (self.opts.log_dir, timestamp), 'wb')
        fout.write(fin.read())
        fin.close()
        fout.close()

    ################################################################################
    # Handles access violations
    ###
    def av_handler(self, dbg):
        # cancel process termination timer
        self.timer.cancel()

        print "[!] ACCESS VIOLATION"

        timestamp = time.strftime("%m%d_%H-%M-%S", time.localtime())
        self.create_backup(timestamp)

        crash_bin = crash_binning()
        crash_bin.record_crash(dbg)

        f = open("%s%s_dbg.txt" % (self.opts.log_dir, timestamp), 'w')
        f.write(crash_bin.crash_synopsis())
        f.close()

        self.kill_proc()

        return DBG_CONTINUE

    #FIXME: if cntl-c detected, suspend dbg thread
    #def suspend(self):
        #self.dbg.suspend_all_threads()

    #def resume(self):
        #self.dbg.resume_all_threads()

    ################################################################################
    # Invokes the pydbg
    ###
    def fuzz(self):
        self.dbg = pydbg()
        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.av_handler)
        self.dbg.load(self.opts.exe, self.opts.fuzzed_file)
        self.dbg.run()

# public funtions
def enable_gflags(exe):
    cmd = "%s /p /enable %s /full" % (gflags_path, exe)
    subprocess.call(cmd)

def disable_gflags(exe):
    cmd = "%s /p /disable %s /full" % (gflags_path, exe)
    subprocess.call(cmd)

from pydbg import *
from pydbg.defines import *

# obtained from the paimei project: https://github.com/OpenRCE/paimei/blob/master/utils/crash_binning.py
from crash_binning import *

import threading
import subprocess

log_file = "C:\\crash.log"
use_gflags = True
gflags_path = "C:\\Program Files\\Windows Kits\\8.1\\Debuggers\\x86\\gflags.exe"

class pyDbgFuzz:
    def __init__(self, target_exe, fuzz_file=None):
        self.target_exe = target_exe
        self.fuzz_file = fuzz_file

        self.exe = target_exe[target_exe.rfind("\\")+1:]

        if use_gflags:
            self.enable_gflags()

        self.t = threading.Thread(target=self.fuzz)
        self.t.start()

    def enable_gflags(self):
        cmd = "%s /p /enable %s /full" % (gflags_path, self.exe)
        subprocess.call(cmd)

    def disable_gflags(self):
        cmd = "%s /p /disable %s /full" % (gflags_path, self.target_exe)
        subprocess.call(cmd)

    def kill_python(self):
        subprocess.call("taskkill /t /f /im python.exe")

    def bp_handler(self):
        if self.dbg.first_breakpoint:
            self.dbg.hide_debugger

        return DBG_CONTINUE

    def av_handler(self):
        if self.dbg.dbg.u.Exception.dwFirstChance:
            return EXCEPTION_NOT_HANDLED

        print "[!] ACCESS VIOLATION"

        self.crash_bin = crash_binning()
        self.crash_bin.record_crash(self.dbg)

        f = open(log_file, 'w')
        f.write(self.crash_bin.crash_synopsis())
        f.close()

        if use_gflags:
            self.disable_gflags()

        self.kill_python()

    def fuzz(self):
        self.dbg = pydbg()
        self.dbg.set_callback(EXCEPTION_BREAKPOINT, self.bp_handler)
        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.av_handler)
        self.dbg.load(self.target_exe, self.fuzz_file)
        self.dbg.run()

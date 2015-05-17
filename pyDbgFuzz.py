from pydbg import *
from pydbg.defines import *

# obtained from the paimei project: https://github.com/OpenRCE/paimei/blob/master/utils/crash_binning.py
from crash_binning import *

import threading
import subprocess
import time

crash_dir = "C:\\crashdir\\"
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

    def close_fault_win(self):
        tasklist = subprocess.check_output("tasklist")

        fault_win = "WerFault.exe"
        if fault_win in tasklist:
            subprocess.call("taskkill /t /f /im %s" % fault_win)

    def kill_proc(self, timeout):
        time.sleep(timeout)
        self.close_fault_win()
        subprocess.call("taskkill /t /f /im %s" % self.exe)
        time.sleep(0.2)

    def kill_python(self):
        subprocess.call("taskkill /t /f /im python.exe")

    def create_backup(self, timestamp):
            fin = open(self.fuzz_file, 'rb')
            fout = open("%s%s_poc.bak" % (crash_dir, timestamp), 'wb')
            fout.write(fin.read())
            fin.close()
            fout.close()

    def av_handler(self, dbg):
        if dbg.dbg.u.Exception.dwFirstChance:
            return DBG_EXCEPTION_NOT_HANDLED

        print "[!] ACCESS VIOLATION"

        timestamp = time.strftime("%m%d_%H-%M-%S", time.localtime())
        self.create_backup(timestamp)

        crash_bin = crash_binning()
        crash_bin.record_crash(dbg)

        f = open("%s%s_dbg.txt" % (crash_dir, timestamp), 'w')
        f.write(crash_bin.crash_synopsis())
        f.close()

        if use_gflags:
            self.disable_gflags()

        self.kill_python()

    def fuzz(self):
        self.dbg = pydbg()
        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.av_handler)
        self.dbg.load(self.target_exe, self.fuzz_file)
        self.dbg.run()
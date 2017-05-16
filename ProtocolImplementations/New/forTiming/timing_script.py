import sys, os, subprocess

def test():
    child = subprocess.Popen(['python3', '-m', 'da', '/home/Christopher/secalgo/ProtocolsImplementations/New/ns-sk.da'], bufsize= -1, stdout = subprocess.PIPE,
                     stderr = subprocess.PIPE, universal_newlines = True)
    stdout, stderr = child.communicate()
    print(stdout)
#end test()

if __name__ == '__main__':
    test()

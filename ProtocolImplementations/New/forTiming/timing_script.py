import sys, os, subprocess

full_path = '/home/Christopher/secalgo/ProtocolImplementations/New/forTiming'

protocol_files = ['ds-ft.da', 'ds-pk-ft.da', 'ns-sk-ft.da', 'ns-pk-ft.da',
                  'or-ft.da', 'wl-ft.da', 'ya-ft.da',  'dhke-1-ft.da', 
                  'eke-ft.da', 'sdh-ft.eke', 'eap_archie-ft.da', 'tls1_2-ft.da',
                  'kerberos-ft.da', 'iso9798-3-4-ft.da']

def time_exp01(protocol):
    for fn in protocol_files:
        child = subprocess.Popen(['python3', '-m', 'da', full_path + fn], 
                                 bufsize= -1, stdout = subprocess.PIPE,
                                 stderr = subprocess.PIPE, 
                                 universal_newlines = True)
        stdout, stderr = child.communicate()
        print(stdout)
#end time_exp01()

if __name__ == '__main__':
    time_exp01()

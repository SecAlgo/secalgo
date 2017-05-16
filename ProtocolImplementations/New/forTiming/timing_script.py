import sys, os, subprocess, time

full_path = '/home/christopher/secalgo/ProtocolImplementations/New/forTiming/'
result_path = '/home/christopher/secalgo/results/'

da_ext = '.da'
results_ext = '_results.txt'
error_ext = '_results.log'

protocols = [
                  'ds-ft',
                  'ds-pk-ft',
                  #'ns-sk-ft',
                  #'ns-pk-ft',
                  #'or-ft',
                  #'wl-ft',
                  #'ya-ft',
                  #'dhke-1-ft',
                  #'eap_archie-ft.da',
                  #'eke-ft.da',
                  #'iso9798-3-4-ft.da'
                  #'sdh-ft',
                  #'tls1_2-ft.da',
                  #'kerberos-ft.da',
                 ]

def time_exp01():
    for p in protocols:
        print('Running:', p, flush = True)
        f_txt = open(result_path + p + results_ext, 'w')
        f_err = open(result_path + p + error_ext, 'w')
        child = subprocess.Popen(['python3', '-m', 'da', full_path + p + da_ext], 
                                 bufsize= -1,
                                 stdout = f_txt,
                                 stderr = f_err, 
                                 universal_newlines = True)
        child.wait()
        #stdout, stderr = child.communicate()
        #print(stdout, flush = True)
        f_txt.close()
        f_err.close()
        print('Finished:', p, flush = True)
        time.sleep(1)
#end time_exp01()

if __name__ == '__main__':
    time_exp01()

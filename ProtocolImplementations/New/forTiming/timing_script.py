import sys, os, subprocess, time

full_path = '/home/christopher/secalgo/ProtocolImplementations/New/forTiming/'
result_path = '/home/christopher/secalgo/results/'

da_ext = '.da'
results_ext = '_results.txt'
error_ext = '_results.log'

sec_algo_functions('genkey', 'encrypt', 'decrypt', 'sign', 'verify', 'verify1'
                   'gen_nonce')

protocols = [
                  'ds-ft',
                  #'ds-pk-ft',
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

p_main_skip = {
               'ds-ft' : 2,
               #'ds-pk-ft' : 2,
               #'ns-sk-ft' : 2,
               #'ns-pk-ft' : 3,
               #'or-ft' : 2,
               #'wl-ft' : 2,
               #'ya-ft' : 2,
               }
                 
def time_exp01():
    print('Timing Experiment 01', flush = True)
    for i in range(10):
        print('Iteration ' + str(i + 1) + ':', flush = True)
        for p in protocols:
            print('Running:', p, flush = True)
            f_txt = open(result_path + p + '_' + str(i + 1) + results_ext, 'w')
            f_err = open(result_path + p + '_' + str(i + 1) + error_ext, 'w')
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
            print('Finished', p, flush = True)
            time.sleep(1)
        print('Completed Iteration', str(i + 1), flush = True)
        time.sleep(1)
    print('Completed Timing Experiment 01', flush = True)
#end time_exp01()

def parse_exp01()
    for p in protocols:
        function_skip = p_main_skip[p]
        for i in range(10):
            with open(result_path + p + '_' + str(i + 1) + results_ext, 'r') as f:
                for read_line in f:
                    skip_counter = 0
                    data_line = json.loads(read_line)
                    if data_line[0] == 'genkey' and skip_counter < function_skip:
                        skip_counter += 1
                    
                
      
#end parse_exp01()


if __name__ == '__main__':
    time_exp01()

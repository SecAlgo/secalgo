import sys, os, subprocess, time, json

full_path = '/home/christopher/secalgo/ProtocolImplementations/New/forTiming/'
result_path = '/home/christopher/secalgo/results/'

da_ext = '.da'
results_ext = '_results.txt'
error_ext = '_results.log'

sec_algo_functions = (
                      'genkey',
                      'encrypt',
                      'decrypt',
                      'sign',
                      'verify',
                      'verify1',
                      'gen_nonce'
                     )

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

p_main_skip = {
               'ds-ft' : 2,
               'ds-pk-ft' : 3,
               #'ns-sk-ft' : 2,
               #'ns-pk-ft' : 3,
               #'or-ft' : 2,
               #'wl-ft' : 2,
               #'ya-ft' : 2,
               }
                 
def time_exp01(iter_num):
    print('Timing Experiment 01', flush = True)
    for i in range(iter_num):
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

def parse_exp01(iter_num):
    for p in protocols:
        print('Results for:', p)
        total_library_time = 0
        total_protocol_time = 0
        iter_result_list = []
        function_skip = p_main_skip[p]
        for i in range(iter_num):
            library_time = 0
            protocol_time = 0
            skip_counter = 0
            with open(result_path + p + '_' + str(i + 1) + results_ext, 'r') as f:
                for read_line in f:                    
                    data_line = json.loads(read_line)
                    print(data_line, flush = True)
                    if data_line[0] in sec_algo_functions:
                        print('library', flush = True)
                        if data_line[0] == 'genkey' and skip_counter < function_skip:
                            print('skip', flush = True)
                            skip_counter += 1
                        else:
                            library_time += (data_line[2] - data_line[1])
                    else:
                        print('protocol', flush = True)
                        protocol_time += (data_line[3] - data_line[2])
            ratio = (library_time / protocol_time)
            iter_result = [(i + 1), p, protocol_time, library_time, ratio]
            iter_result_list.append(iter_result)
            print(json.dumps(iter_result))
        for ir in iter_result_list:
            total_library_time += ir[3]
            total_protocol_time += ir[2]
        avg_library_time = total_library_time / iter_num
        avg_protocol_time = total_protocol_time / iter_num
        avg_ratio = avg_library_time / avg_protocol_time
        print(json.dumps(['avg', p, avg_protocol_time, avg_library_time, avg_ratio ]))

#end parse_exp01()


if __name__ == '__main__':
    iter_num = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    time_exp01(iter_num)
    parse_exp01(iter_num)

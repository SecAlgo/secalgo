import sys, os, subprocess, time, json

full_path = '/home/christopher/secalgo/experiments/forTiming/'
result_path = '/home/christopher/secalgo/results/protocol/'
output_path = '/home/christopher/secalgo/output/protocol/'
m_buf_opt = '--message-buffer-size'
m_buf_size = '8192'
da_ext = '.da'
results_ext = '_results.txt'
error_ext = '_error.log'

protocols = [
             'ds',
             'ds-pk',
             'ns-sk',
             'ns-pk',
             'or',
             'wl',
             'ya',
             'dhke-1',
             #'eap_archie',
             #'eke',
             #'iso9798-3-4',
             'sdh',
             'tls1_2',
             'kerberos5'
            ]


def time_exp02(p, iter_num, loops):
    print('Protocol Timing Experiment 01 for:', p, flush = True)
    if p in protocols:
        if p == 'dhke-1' or p == 'tls1_2':
            cmd = ['python3', '-m', 'da', m_buf_opt, m_buf_size, full_path + p + da_ext, loops]
        else:
            cmd = ['python3', '-m', 'da', full_path + p + da_ext, loops]
        print('Running:', cmd, flush = True)
        for i in range(iter_num):
            print('Iteration ' + str(i + 1) + ':', flush = True)
            f_txt = open(result_path + p + '_' + str(i + 1) + results_ext, 'w')
            f_err = open(result_path + p + '_' + str(i + 1) + error_ext, 'w')
            child = subprocess.Popen(cmd, bufsize= -1, stdout = f_txt,
                                     stderr = f_err, universal_newlines = True)
            child.wait()
            #stdout, stderr = child.communicate()
            #print(stdout, flush = True)
            f_txt.close()
            f_err.close()
            
            time.sleep(1)
            print('Completed Iteration', str(i + 1), flush = True)
        print('Finished', p, flush = True)
        print('Completed Timing Experiment 01 for:', p, flush = True)
    else:
        print('No such protocol', p, 'available.', flush = True)    
#end time_exp01()

def parse_exp02(p, iter_num, output_file):
    if output_file == None:
        of = open(output_path + p + '_output_.txt', 'w')
    else:
        of = open(output_file, 'w')
    if p in protocols:
        print('Results for:', p, file = of, flush = True)
        total_protocol_time = 0
        iter_result_list = []
        for i in range(iter_num):
            protocol_time = 0
            with open(result_path + p + '_' + str(i + 1) + results_ext, 'r') as f:
                for read_line in f:                    
                    data_line = json.loads(read_line)
                    print(data_line, file = of, flush = True)
                    print(data_line, flush = True)
                    role_time = ((data_line[3] - data_line[2]) / data_line[4])
                    print('role time:', data_line[0], ':', data_line[1], '-', role_time,
                          file = of, flush = True)
                    protocol_time += role_time
            iter_result = [(i + 1), p, protocol_time]
            iter_result_list.append(iter_result)
            print(json.dumps(iter_result), file = of, flush = True)
        for ir in iter_result_list:
            total_protocol_time += ir[2]
        avg_protocol_time = total_protocol_time / iter_num
        print(json.dumps(['avg', p, avg_protocol_time]), file = of, flush = True)
        print(json.dumps(['avg', p, avg_protocol_time]), flush = True)
        of.close()
#end parse_exp01()

if __name__ == '__main__':
    proto = sys.argv[1] if len(sys.argv) > 1 else 'all'
    iter_num = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    loops = sys.argv[3] if len(sys.argv) > 3 else ''
    output_file = sys.argv[4] if len(sys.argv) > 4 else None
    if proto == 'all':
        for p in protocols:
            time_exp02(p, iter_num, loops)
            parse_exp02(p, iter_num, output_file)
    else:
        time_exp02(proto, iter_num, loops)
        parse_exp02(proto, iter_num, output_file)

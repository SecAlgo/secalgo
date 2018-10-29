import sys, os, subprocess, time, json, argparse

full_path = '/home/christopher/secalgo/protocols/new/python/ns/'
result_path = '/home/christopher/secalgo/protocols/new/python/ns/'
output_path = '/home/christopher/secalgo/protocols/new/python/ns/'
#m_buf_opt = '--message-buffer-size'
#m_buf_size = '8192'
#da_ext = '.da'
py_ext = '.py'
results_ext = '_results.txt'
error_ext = '_error.log'

sec_algo_functions = ('keygen',
                      'encrypt',
                      'decrypt',
                      'sign',
                      'verify',
                      'nonce',
                      'BitGen',
                      'key_derivation',
                      'local_pow',
                      'tls_prf_sha256')

protocols = ['ns_sk_fixed_python2L']

p_main_skip = {'ns_sk_fixed_python2L' : 2}

                 
def time_exp01(p, iter_num, iter_label):
    print('Library Timing Experiment 01 for:', p, flush = True)
    if p in protocols:
        cmd = ['python3', full_path + p + py_ext]
        print('Running:', cmd, flush = True)
        if iter_num:
            the_range = range(iter_num)
        else:
            the_range = range((iter_label - 1), iter_label)
        for i in the_range:
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

def parse_exp01(p, iter_num, iter_label, output_file):
    if output_file == None:
        of = open(output_path + p + '_output.txt', 'w')
    else:
        of = open(output_file, 'w')
    if p in protocols:
        print('Results for:', p, file = of, flush = True)
        total_library_time = 0
        function_times = []
        iter_result_list = []
        function_skip = p_main_skip[p]
        if iter_num:
            iter_count = iter_num
        else:
            iter_count = iter_label
        for i in range(iter_count):
            library_time = 0
            skip_counter = 0
            with open(result_path + p + '_' + str(i + 1) + results_ext, 'r') as f:
                for read_line in f:                    
                    data_line = json.loads(read_line)
                    #print(data_line, file = of, flush = True)
                    if data_line[0] in sec_algo_functions:
                        #print('library', file = of, flush = True)
                        if ((data_line[0] == 'keygen' or data_line[0] == 'sign') and
                            skip_counter < function_skip):
                            #print('skip', file = of, flush = True)
                            print('SKIP:', data_line, flush = True)
                            skip_counter += 1
                        else:
                            function_time = (((data_line[2] - data_line[1]) / data_line[3])
                                             * 1000)
                            #print('function time:', data_line[0], '-', function_time,
                            #      file = of, flush = True)
                            function_times.append(((i+1), data_line[0], function_time))
                            print(str(i+1) + ': ' + data_line[0] + ':', data_line[2],
                                  '-', data_line[1], '/', data_line[3], '=',
                                  function_time, flush = True)
                            library_time += function_time
            iter_result = [(i + 1), p, library_time]
            iter_result_list.append(iter_result)
            #print(json.dumps(iter_result), file = of, flush = True)
            print(iter_result, flush = True)
        for ir in iter_result_list:
            total_library_time += ir[2]
        avg_library_time = total_library_time / iter_count
        for ft in function_times:
            print(str(ft[0]) + '\t' + ft[1] + '\t' + str(ft[2]), file = of, flush = True)
        for irt in iter_result_list:
            print(str(irt[0]) + '\t' + irt[1] + '\t' + str(irt[2]), file = of, flush = True)
        print(json.dumps(['avg', p, total_library_time,
                          iter_count, avg_library_time]), file = of, flush = True)
        print('avg for ' + p + ':', total_library_time, '/',
              iter_count, '=', avg_library_time, flush = True)
        of.close()
#end parse_exp01()

def init_arg_parser():
    parser = argparse.ArgumentParser(description = "Run protocol timing experiments:")
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument('-i', '--iterations', type = int,
                        help = 'number of times protocol timing experiment will run')
    group.add_argument('-I', '--iteration-label', type = int,
                       help = 'run a single iteration with the given integer label')
    parser.add_argument('-o', '--output-file',
                        help = 'name of output file')
    parser.add_argument('proto',
                        help = 'name of the file (sans extension) containing the protocol one wishes to run')
    return parser
#end init_arg_parser()

if __name__ == '__main__':
    parser = init_arg_parser()
    args = parser.parse_args(sys.argv[1:])
    if args.proto == 'all':
        for p in protocols:
            time_exp01(p, args.iterations, args.iteration_label)
            parse_exp01(p, args.iterations, args.iteration_label, args.output_file)
    else:
        time_exp01(args.proto, args.iterations, args.iteration_label)
        parse_exp01(args.proto, args.iterations, args.iteration_label, 
                    args.output_file)

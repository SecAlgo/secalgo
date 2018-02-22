import sys, os, subprocess, time, json, argparse
#from sa import secalgoB.useTimers
#from sa import secalgoB.proto_loops
#from sa import sec_algo_pycrypto.usePickleTimer
#from sa import sec_algo_pycrypto.pickle_loops
import sa.secalgoB as SA
import sa.sec_algo_pycrypto as SA_PyCrypto
sa_path = '/home/christopher/secalgo/'
full_path = sa_path + 'ProtocolImplementations/New/'
raw_path = sa_path + 'experiments/timing_20180218/rawData/'
results_path = sa_path + 'experiments/timing_20180218/results/'
m_buf_opt = '--message-buffer-size'
m_buf_size = '8192'
da_ext = '.da'
results_ext = '_results.txt'
error_ext = '_error.log'

protocols = ['ns-sk_fixedT', 'pc_ns-sk_fixedT', 'pc_ns-sk_fixedL', 'pc_ns-sk_fixedP']

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

p_main_skip = {'ns-sk_fixedT' : 2,
               'pc_ns-sk_fixedL' : 0}

#protocols = ['ds',
#             'ds-pk',
#             'ns-sk',
#             'ns-sk_fixed',
#             'ns-pk',
#             'or',
#             'wl',
#             'ya',
#             'dhke-1',
#             'sdh',
#             'tls1_2',
#             'kerberos5',
#             'test_proto']

def measure_proto_time(p, iter_num, iter_label, loops):
    print('Protocol Timing Experiment for:', p, flush = True)
    if p in protocols:
        if p == 'dhke-1' or p == 'tls1_2' or p == 'ds-pk':
            cmd = ['python3', '-m', 'da', m_buf_opt, m_buf_size,
                   full_path + p + da_ext, str(loops)]
        else:
            cmd = ['python3', '-m', 'da', full_path + p + da_ext, str(loops)]
        print('Running:', cmd, flush = True)
        if iter_num:
            the_range = range(iter_num)
        else:
            the_range = range((iter_label - 1), iter_label)        
        for i in the_range:
            print('Iteration ' + str(i + 1) + ':', flush = True)
            f_txt = open(raw_path + 'protocol/' + p + '_' + str(i + 1) + results_ext, 'w')
            f_err = open(raw_path + 'protocol/' + p + '_' + str(i + 1) + error_ext, 'w')
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
        print('Completed Protocol Timing Experiment for:', p, flush = True)
    else:
        print('No such protocol', p, 'available.', flush = True)
#end measure_proto_time()

def parse_proto_time(p, iter_num, iter_label, output_file):
    if output_file == None:
        of = open(results_path + 'protocol/' + p + '_output.txt', 'w')
    else:
        of = open(output_file, 'w')
    if p in protocols:
        print('Results for:', p, file = of, flush = True)
        total_protocol_time = 0
        iter_result_list = []
        if iter_num:
            iter_count = iter_num
        else:
            iter_count = iter_label
        for i in range(iter_count):
            protocol_time = 0
            with open(raw_path + 'protocol/' + p + '_' + str(i + 1) + results_ext, 'r') as f:
                for read_line in f:                    
                    data_line = json.loads(read_line)
                    print(data_line, file = of, flush = True)
                    print(data_line, flush = True)
                    # miliseconds
                    role_time = (((data_line[3] - data_line[2]) / data_line[4]) * 1000)
                    print('role time:', data_line[0], ':', data_line[1], '-', role_time,
                          file = of, flush = True)
                    protocol_time += role_time
            protocol_time = protocol_time
            iter_result = [(i + 1), p, protocol_time]
            iter_result_list.append(iter_result)
            print(json.dumps(iter_result), file = of, flush = True)
        for ir in iter_result_list:
            total_protocol_time += ir[2]
        total_protocol_time = total_protocol_time
        avg_protocol_time = total_protocol_time / iter_count
        print(json.dumps(['avg', p, total_protocol_time, iter_count, 
                          avg_protocol_time]), file = of, flush = True)
        print('avg for ' + p + ':', total_protocol_time, '/', iter_count, '=',
              avg_protocol_time, flush = True)
        of.close()
#end parse_proto_time()

def measure_lib_time(p, iter_num, iter_label):
    print('Library Timing Experiment for:', p, flush = True)
    if p in protocols:
        if p == 'dhke-1L' or p == 'ds-pkL' or p == 'sdhL' or p == 'tls1_2L':
            cmd = ['python3', '-m', 'da', m_buf_opt, m_buf_size, full_path + p + da_ext]
        else:
            cmd = ['python3', '-m', 'da', full_path + p + da_ext]
        print('Running:', cmd, flush = True)
        if iter_num:
            the_range = range(iter_num)
        else:
            the_range = range((iter_label - 1), iter_label)
        for i in the_range:
            print('Iteration ' + str(i + 1) + ':', flush = True)
            f_txt = open(raw_path + 'library/' + p + '_' + str(i + 1) + results_ext, 'w')
            f_err = open(raw_path + 'library/' + p + '_' + str(i + 1) + error_ext, 'w')
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
        print('Completed Library Timing Experiment for:', p, flush = True)
    else:
        print('No such protocol', p, 'available.', flush = True)
#end measure_lib_time()

def parse_lib_time(p, iter_num, iter_label, output_file):
    if output_file == None:
        of = open(results_path + 'library/' + p + '_output.txt', 'w')
    else:
        of = open(output_file, 'w')
    if p in protocols:
        print('Results for:', p, file = of, flush = True)
        total_library_time = 0
        iter_result_list = []
        function_skip = p_main_skip[p]
        if iter_num:
            iter_count = iter_num
        else:
            iter_count = iter_label
        for i in range(iter_count):
            library_time = 0
            skip_counter = 0
            with open(raw_path + 'library/' + p + '_' + str(i + 1) + results_ext, 'r') as f:
                for read_line in f:
                    data_line = json.loads(read_line)
                    print(data_line, file = of, flush = True)
                    if data_line[0] in sec_algo_functions:
                        print('library', file = of, flush = True)
                        if ((data_line[0] == 'keygen' or data_line[0] == 'sign') and
                            skip_counter < function_skip):
                            print('skip', file = of, flush = True)
                            print('SKIP:', data_line, flush = True)
                            skip_counter += 1
                        else:
                            function_time = (((data_line[2] - data_line[1]) / data_line[3])
                                             * 1000)
                            print('function time:', data_line[0], '-', function_time,
                                  file = of, flush = True)
                            print(str(i+1) + ': ' + data_line[0] + ':', data_line[2],
                                  '-', data_line[1], '/', data_line[3], '=',
                                  function_time, flush = True)
                            library_time += function_time
            iter_result = [(i + 1), p, library_time]
            iter_result_list.append(iter_result)
            print(json.dumps(iter_result), file = of, flush = True)
            print(iter_result, flush = True)
        for ir in iter_result_list:
            total_library_time += ir[2]
        avg_library_time = total_library_time / iter_count
        print(json.dumps(['avg', p, total_library_time, iter_count, avg_library_time]),
              file = of, flush = True)
        print('avg for ' + p + ':', total_library_time, '/', iter_count, '=',
              avg_library_time, flush = True)
        of.close()
#end parse_lib_time()

def measure_pickle_time(p, iter_num, iter_label):
    print('Pickle Timing Experiment for:', p, flush = True)
    if p in protocols:
        if p == 'dhke-1' or p == 'tls1_2' or p == 'ds-pk':
            cmd = ['python3', '-m', 'da', m_buf_opt, m_buf_size,
                   full_path + p + da_ext]
        else:
            cmd = ['python3', '-m', 'da', full_path + p + da_ext]
        print('Running:', cmd, flush = True)
        if iter_num:
            the_range = range(iter_num)
        else:
            the_range = range((iter_label - 1), iter_label)        
        for i in the_range:
            print('Iteration ' + str(i + 1) + ':', flush = True)
            f_txt = open(raw_path + 'pickle/' + p + '_' + str(i + 1) + results_ext, 'w')
            f_err = open(raw_path + 'pickle/' + p + '_' + str(i + 1) + error_ext, 'w')
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
        print('Completed Pickle Timing Experiment for:', p, flush = True)
    else:
        print('No such protocol', p, 'available.', flush = True)
#end measure_pickle_time()

def parse_pickle_time(p, iter_num, iter_label, output_file):
    if output_file == None:
        of = open(results_path + 'pickle/' + p + '_output.txt', 'w')
    else:
        of = open(output_file, 'w')
    if p in protocols:
        print('Results for:', p, file = of, flush = True)
        total_pickle_time = 0
        iter_result_list = []
        if iter_num:
            iter_count = iter_num
        else:
            iter_count = iter_label
        for i in range(iter_count):
            pickle_time = 0
            with open(raw_path + 'pickle/' + p + '_' + str(i + 1) + results_ext, 'r') as f:
                for read_line in f:                    
                    data_line = json.loads(read_line)
                    print(data_line, file = of, flush = True)
                    print(data_line, flush = True)
                    # miliseconds
                    fp_time = (((data_line[3] - data_line[2]) / data_line[4]) * 1000)
                    print(data_line[1], ':', data_line[0], '-', fp_time,
                          file = of, flush = True)
                    pickle_time += fp_time
            iter_result = [(i + 1), p, pickle_time]
            iter_result_list.append(iter_result)
            print(json.dumps(iter_result), file = of, flush = True)
        for ir in iter_result_list:
            total_pickle_time += ir[2]
        avg_pickle_time = total_pickle_time / iter_count
        print(json.dumps(['avg', p, total_pickle_time, iter_count, 
                          avg_pickle_time]), file = of, flush = True)
        print('avg for ' + p + ':', total_pickle_time, '/', iter_count, '=',
              avg_pickle_time, flush = True)
        of.close()
#end parse_proto_time()

def init_arg_parser():
    parser = argparse.ArgumentParser(description = 'Run timing' + 
                                     ' experiments:')
    group = parser.add_mutually_exclusive_group(required = True)
    group.add_argument('-i', '--iterations', type = int,
                       help = 'number of times protocol timing' + 
                       ' experiment will run')
    group.add_argument('-I', '--iteration-label', type = int,
                       help = 'run a single iteration with the given' + 
                       ' integer label')
    parser.add_argument('-l', '--loops', default = 1,
                        help = 'number of times each protocol will be run' +
                        ' during a single iteration of the experiment')
    parser.add_argument('-o', '--output-file',
                        help = 'name of output file')
    parser.add_argument('-t', '--test-type',
                        help = 'name of value to be measured')
    parser.add_argument('proto',
                        help = 'name of the file (sans extension) containing' + 
                        ' the protocol one wishes to run')
    return parser
#end init_arg_parser()

if __name__ == '__main__':
    parser = init_arg_parser()
    args = parser.parse_args(sys.argv[1:])
    if args.test_type == 'protocol':
        if args.proto == 'all':
            for p in protocols:
                measure_proto_time(p, args.iteration_num, args.iteration_label, args.loops)
                parse_proto_time(p, args.iter_num, args.iteration_label, 
                                 args.output_file)
        else:
            measure_proto_time(args.proto, args.iterations, args.iteration_label, 
                               args.loops)
            parse_proto_time(args.proto, args.iterations, args.iteration_label, 
                             args.output_file)
    elif args.test_type == 'library':
        if args.proto == 'all':
            for p in protocols:
                measure_lib_time(p, args.iteration_num, args.iteration_label)
                parse_lib_time(p, args.iter_num, args.iteration_label, 
                                 args.output_file)
        else:
            measure_lib_time(args.proto, args.iterations, args.iteration_label)
            parse_lib_time(args.proto, args.iterations, args.iteration_label, 
                             args.output_file)
    elif args.test_type == 'pickle':
        if args.proto == 'all':
            for p in protocols:
                measure_pickle_time(p, args.iteration_num, args.iteration_label)
                parse_pickle_time(p, args.iter_num, args.iteration_label, 
                                  args.output_file)
        else:
            measure_pickle_time(args.proto, args.iterations, args.iteration_label)
            parse_pickle_time(args.proto, args.iterations, args.iteration_label, 
                              args.output_file)

import sys, os, subprocess, time, json, argparse

full_path = '/home/christopher/secalgo/experiments/timing/protocol/'
result_path = '/home/christopher/secalgo/experiments/timing/protocol/results/'
output_path = '/home/christopher/secalgo/experiments/timing/protocol/output/'
m_buf_opt = '--message-buffer-size'
m_buf_size = '8192'
da_ext = '.da'
results_ext = '_results.txt'
error_ext = '_error.log'

protocols = [
             'ds',
             'ds-pk',
             'ns-sk',
             'ns-sk_fixed',
             'ns-pk',
             'or',
             'wl',
             'ya',
             'dhke-1',
             'sdh',
             'tls1_2',
             'kerberos5',
             'test_proto'
            ]


def time_exp02(p, iter_num, iter_label, loops):
    print('Protocol Timing Experiment 01 for:', p, flush = True)
    if p in protocols:
        if p == 'dhke-1' or p == 'tls1_2' or p == 'ds-pk':
            cmd = ['python3', '-m', 'da', m_buf_opt, m_buf_size, full_path + p + da_ext, loops]
        else:
            cmd = ['python3', '-m', 'da', full_path + p + da_ext, loops]
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

def parse_exp02(p, iter_num, iter_label, output_file):
    if output_file == None:
        of = open(output_path + p + '_output.txt', 'w')
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
            with open(result_path + p + '_' + str(i + 1) + results_ext, 'r') as f:
                for read_line in f:                    
                    data_line = json.loads(read_line)
                    print(data_line, file = of, flush = True)
                    print(data_line, flush = True)
                    role_time = ((data_line[3] - data_line[2]) / data_line[4])
                    print('role time:', data_line[0], ':', data_line[1], '-', role_time,
                          file = of, flush = True)
                    protocol_time += role_time
            protocol_time = protocol_time * 1000 # miliseconds
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
#end parse_exp01()

def init_arg_parser():
    parser = argparse.ArgumentParser(description = 'Run protocol timing' + 
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
    parser.add_argument('proto',
                        help = 'name of the file (sans extension) containing' + 
                        ' the protocol one wishes to run')
    return parser
#end init_arg_parser()

if __name__ == '__main__':
    parser = init_arg_parser()
    args = parser.parse_args(sys.argv[1:])
    if args.proto == 'all':
        for p in protocols:
            time_exp02(p, args.iteration_num, args.iteration_label, args.loops)
            parse_exp02(p, args.iter_num, args.iteration_label, 
                        args.output_file)
    else:
        time_exp02(args.proto, args.iterations, args.iteration_label, 
                   args.loops)
        parse_exp02(args.proto, args.iterations, args.iteration_label, 
                    args.output_file)

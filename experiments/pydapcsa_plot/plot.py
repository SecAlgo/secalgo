import matplotlib.pyplot as plt

base_path = '/home/christopher/secalgo/experiments/pydapcsa_plot/'
results_ext = '_output.txt'

rounds = [2000, 4000, 6000, 8000, 10000]

protocols = ['ns-sk_fixedT',
             'pc_ns-sk_fixedT']

def read_results_file(p, r, d):
    res_path = 'm_' + str(r) + '_' + str(d) + '/results/'
    file_path = base_path + res_path + p + results_ext
    f = open(file_path, 'r')
    lines = list(f.read())
    result = json.loads(lines[-1])[4]
    return result



def show_result(x_axis, y_axis):
    plt.clf()
    plt.title('Total CPU Time {1}')
    plt.xlabel('Rounds')
    plt.ylabel('Times(Seconds)')
    plt.plot(x_axis, y_axis, 'r--')
    plt.axis([x_axis[0], x_axis[-1], y_axis[0], y_axis[-1]])
    
    
    
    plt.show()

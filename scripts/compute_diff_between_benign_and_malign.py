from os import listdir, makedirs
from os.path import isfile, join
import csv

src_dir   = "../output"
diffs_dir = f"{src_dir}/diffs"

makedirs(diffs_dir, exist_ok = True)

tools = ['droidbot']

files = [f for f in listdir(src_dir) if isfile(join(src_dir, f)) and f.endswith('csv')]

benign_apps    = {}
malicious_apps = {}

print(f"[Info] Processing files in {src_dir}")
print(f"[Info] Number of files: {len(files)}")  

methods_in_diff = {}

sensitive_methods = []

with open('sensitive_methods.txt', 'r') as fh:
    lines = fh.readlines()

    for line in lines:
        sensitive_methods.append(line.replace('\n', ''))
        
for f in files:
    elements = f.split('-')

    if len(elements) < 4:
        continue
    
    tool = elements[0]
    classification = elements[1]
    apk = elements[2] + "-" + elements[3]

    if tool not in tools:
        continue

    with open(join(src_dir, f)) as fh:
        lines = csv.reader(fh)

        methods = {}

        for line in lines:
            method = line[0]
            parsed_args = [x for x in line[1:]]
            args = ';'.join(parsed_args)

            if method in sensitive_methods:
                if method not in methods:
                    methods[method] = set()

                methods[method].add(args)
                
    if classification == 'benign':
        benign_apps[(tool, apk)] = methods
    elif classification == 'malicious':
        malicious_apps[(tool, apk)] = methods
    else:
        continue

summary = {} 

for (tool, apk) in benign_apps.keys() & malicious_apps.keys():
    file_name = f"{diffs_dir}/{tool}-diff-{apk}.csv"
    summary[(tool, apk)] = 0

    with open(file_name, 'w') as fh:
        for method in benign_apps[(tool, apk)].keys() & malicious_apps[(tool, apk)].keys():
            pdMethods = malicious_apps[(tool, apk)][method].difference(benign_apps[(tool, apk)][method])

            summary[(tool, apk)] += len(pdMethods)
            
            for args in pdMethods:
                fh.write(method + ";" + args + "\n")
            fh.write("\n")

    print(summary)
                
    summary_file = f"{diffs_dir}/summary.csv"
    with open(summary_file, 'w') as fh:
        fh.write("tool,apk,param_methods_in_diff\n")
        for ((tool, apk), ms) in summary.items():
            fh.write(f"{tool},{apk},{ms}\n")
            
print(f"[Info] Results exported to {diffs_dir}")


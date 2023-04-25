from os import listdir
from os.path import isfile, join

src_dir   = "../output"
diffs_dir = f"{src_dir}/diffs"

tools = ['droidbot']

files = [f for f in listdir(src_dir) if isfile(join(src_dir, f)) and f.endswith('csv')]

benign_apps    = {}
malicious_apps = {}

benign_apps_param    = {}
malicious_apps_param = {}

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
        lines = fh.readlines()

        methods = set()
        params  = set()
        
        for line in lines:
            method = line.replace('\n', '')
            method = line[line.find('<'):line.find('>')+1]
            param = line[line.find(';')+1:]
            if method in sensitive_methods:  
                methods.add(method)
                #if (param.find('X-ADMOB-ISU') != -1):
                params.add(param)
                #if (param.find('AdMobSDK') != -1):
                #    params.add(param)
                

    if classification == 'benign':
        benign_apps[(tool, apk)] = methods
        benign_apps_param[(tool, apk)] = params
    elif classification == 'malicious':
        malicious_apps[(tool, apk)] = methods
        malicious_apps_param[(tool, apk)] = params
    else:
        continue

summary = {} 

for (tool, apk), bMethods in benign_apps.items():
    for (tool, apk), mMethods in malicious_apps.items():
    
        if bMethods == mMethods:
            
            mMethods = malicious_apps.get((tool, apk), set())
            
            pmMethods = malicious_apps_param.get((tool, apk), set())
            pbMethods = benign_apps_param.get((tool, apk), set())
            
            pdMethods = pmMethods.difference(pbMethods)
            summary[(tool, apk)] = len(pdMethods)
            file_name = f"{diffs_dir}/{tool}-diff-{apk}.csv"
            
            with open(file_name, 'w') as fh:
                fh.writelines(pdMethods)
               
            summary_file = f"{diffs_dir}/summary.csv"
            with open(summary_file, 'w') as fh:
                fh.write("tool,apk,param_methods_in_diff\n")
                for ((tool, apk), ms) in summary.items():
                    fh.write(f"{tool},{apk},{ms}\n")
                
            
print(f"[Info] Results exported to {diffs_dir}")


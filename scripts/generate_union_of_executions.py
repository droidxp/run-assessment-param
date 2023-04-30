"""Compute the union of sensitive method calls during DroidXP executions. 

   Description: Given three executions for DroidBot, for instance,
   this script computes the union of the calls to sensitive methods 
   for a given app. 
"""
import os
import csv

tools = ['droidbot']
executions = [1,2,3]
non_relevant_categories = [] 

print(f"[Info] Computing the union of executions {executions}")
print(f"[Info] Tools: {tools}")
print(f"[Info] Searching for files named sensitiveMtdArgs.csv")

mapping = {} # a dictionary mapping (tool, apk) into a set of methods. 

for root, dirs, files in os.walk('..'):
    for f in files:
        if f.endswith('sensitiveMtdArgs.csv'):
            relative_path = os.path.join(root, f)

            elements = relative_path.split('/')

            execution = int(elements[2])
            tool = elements[3]
            apk = elements[4]

            print(elements)
            print(f"[Info] {tool} - {execution} - {apk}")
            
            if (tool not in tools) or (execution not in executions):
                continue

            methods_param = mapping.get((tool, apk), set())

            with open(relative_path) as fh:
                lines = csv.reader(fh)

                for line in lines:
                    method = line[0]
                    params = ['"' + x.replace('"', '""') + '"' for x in line[1:]]
                    params = ','.join(params)
                    
                    method_param = '"' + method + '",' + params + '\n'
                    
                    methods_param.add(method_param)

            mapping[(tool,apk)] = methods_param

output_dir = '../output'

os.makedirs(output_dir, exist_ok = True)

for ((tool, apk), methods_param) in mapping.items():
    with open(f"{output_dir}/{tool}-{apk}.csv", 'w') as fh:
        fh.writelines(methods_param)

print(f"[Info] done. Results of the union executions are in {output_dir}")


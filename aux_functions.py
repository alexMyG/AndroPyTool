import os
import shutil
import json
import fnmatch
import subprocess


def list_files(directory, string):
    result = []
    for dirpath, dirnames, files in os.walk(directory):
        for file in fnmatch.filter(files, string):
            result.append(os.path.join(dirpath, file))
    return result


def unzip_apk(analyze_apk):
    # directory = source_directory + os.path.basename(filename).replace('.apk', '')
    directory = analyze_apk.replace('.apk', '/')
    # if not os.path.exists(directory):
    #	os.makedirs(directory)

    command = "java -jar Libraries/apktool.jar d " + analyze_apk + " -o " + directory + " -f"

    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, err = p.communicate()


def cleanup(analyze_apk):
    # directory = source_directory + os.path.basename(filename).replace('.apk', '')
    directory = analyze_apk.replace('.apk', '/')
    shutil.rmtree(directory)


def save_as_json(data, output_name):
    with open(str(output_name), 'w') as fp:
        json.dump(data, fp, indent=4)
    print '[*] Analysis saved into:', str(output_name)


def save_as_csv(data):
    # TODO
    return 0


def load_file(filename):
    with open(filename, 'rb') as text_file:
        lines = text_file.readlines()
    return lines


def check_overloaded_methods(dic):
    # not used
    for key, value in dic.iteritems():
        if len(dic[key].keys()) > 1:
            print '\nOVERCHARGED!!!\n'


def save_single_analysis(name, db):
    with open(name, 'w') as fp:
        json.dump(db, fp, sort_keys=True, indent=4)


def load_from_json(name):
    if os.path.isfile(name):
        with open(name, 'r') as fp:
            data = json.load(fp)
        return data
    else:
        return ['Not available']



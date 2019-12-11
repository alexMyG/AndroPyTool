import sys
import csv
import time
import bson
import json
import os.path
import hashlib
import argparse
import collections
import pandas as pd

from tqdm import tqdm
from os import listdir
from bson import json_util
from pymongo import MongoClient
from features_managment import *
from os.path import isdir, isfile
from collections import OrderedDict
from os.path import join as join_dir
from argparse import RawTextHelpFormatter
from androguard.core.bytecodes import apk
from avclass_caller import get_avclass_label
from datetime import datetime as dt


############################################################
# VARIABLES
############################################################
TIME_EXECUTION = str(time.time()).replace('.','-')
API_PACKAGES_LIST = []
API_CLASSES_LIST = []
API_SYSTEM_COMMANDS = []
OUTPUT_FILE_GLOBAL_JSON = "OUTPUT_ANDROPY_" + TIME_EXECUTION + ".json"
OUTPUT_FILE_GLOBAL_CSV = "OUTPUT_ANDROPY_" + TIME_EXECUTION + ".csv"

POSSIBLE_DYNAMIC_FILES_EXTENSIONS = [".csv", ".json", ".txt"]
############################################################


def main():
    parser = argparse.ArgumentParser(
        description='#Feature extraction script#\n[!]Include the directories "info/" and "reports/" inside the source '
                    'directory\nfor the "general information" and "dynamic analysis" JSONs, respectively.\n[!]Include '
                    '"VT_analysis/" directory inside the source directory with analysis\nJSON from VirusTotal.\n\n'
                    'All files related to the same APK must be named in the same way (i.e. a hash)',
        formatter_class=RawTextHelpFormatter)

    parser.add_argument('-s', '--source', help='Source directory for APKs', required=True)

    parser.add_argument('-l', '--label', help="Sets a label for each sample included into the source directory. "
                                              "If not provided, the folder path from the source directory is used.",
                        required=False)

    parser.add_argument('-S', '--Single', default=True,
                        help='Save single analysis separately. Default: False. A global '
                             'file can be composed with a set of single analysis '
                             'using -j as argument',
                        action='store_true')

    parser.add_argument('-DA', '--DynamicAnalysis', help='Include dynamic analysis available. A folder containing '
                                                         'different subfolders for each dynamic analysis tool should'
                                                         'be provided here.')

    parser.add_argument('-VT', '--VirusTotal', help='Include VirusTotal JSON analysis. Provide folder containing *.json'
                                                    ' files.')

    parser.add_argument('-FW', '--FlowDroid', help='Include FlowDroid analysis. Provide folder containing folders '
                                                   'generated with FlowDroid.')

    parser.add_argument('-o', '--output',
                        help='Output folder name to save analysis. ', required=True)

    parser.add_argument('-c', '--nocleanup', default=False,
                        help='Perform cleanup deleting temporary working files. Default: True', action='store_true')

    parser.add_argument('-P', '--Package', default='info/package_index.txt',
                        help='TXT file with all Android API packages. Default: info/package_index.txt')

    parser.add_argument('-C', '--Class', default='info/class_index.txt',
                        help='TXT file with all Android API classes. Default: info/class_index.txt')

    parser.add_argument('-SC', '--SystemC', default='info/system_commands.txt',
                        help='TXT file with all System Commands. Default: info/system_commands.txt')

    parser.add_argument('-AVC', '--AVClass', default=True,
                        help='Use AVClass to provide a consensual label. Default: True')

    parser.add_argument('-mg', '--mongodbURI', help='Exports the report generated to a mongodb database. Requires '
                                                    'connection address following the scheme: localhost:27017')

    parser.add_argument('-csv', '--exportCSV', help='Exports the report generated to a CSV file. Only static '
                                                    'features are included.')

    args = parser.parse_args()

    features_extractor(apks_directory=args.source, single_analysis=args.Single,
                       dynamic_analysis_folder=args.DynamicAnalysis,
                       virus_total_reports_folder=args.VirusTotal, output_folder=args.output,
                       noclean_up=args.nocleanup, flowdroid_folder=args.FlowDroid, package_index_file=args.Package,
                       classes_index_file=args.Class, system_commands_file=args.SystemC, label=args.label,
                       avclass=args.AVClass, export_mongodb=args.mongodbURI, export_csv=args.exportCSV)


############################################################


############################################################
# MAIN METHOD
############################################################
def features_extractor(apks_directory, single_analysis, dynamic_analysis_folder, virus_total_reports_folder,
                       flowdroid_folder, output_folder, noclean_up, package_index_file, classes_index_file,
                       system_commands_file, label, avclass, export_mongodb, export_csv):
    """
    Extracts features from a set of samples

    Parameters
    ----------
    :param apks_directory: Folder containing apk files
    :param single_analysis: If an individual features file is generated for each sample
    :param dynamic_analysis_folder: Folder containing dynamic analysis reports
    :param virus_total_reports_folder: Folder containing VirusTotal reports
    :param flowdroid_folder: Folder containing flowdroid reports
    :param output_folder: Folder where features files are saved
    :param noclean_up: If unnecesary files generated are removed
    :param package_index_file: File describing Android API packages
    :param classes_index_file: File describing Android API classes
    :param system_commands_file: File describing Android system commands
    :param label: If provided, all samples are labelled according to this argument
    :param avclass: If avclass is executed to obtain a consensual label for each sample
    :param export_mongodb: Mongodb address to write features to a database
    :param export_csv: If the features extracted are saved into a csv file
    """
    source_directory = str(apks_directory)

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Load Android API packages and classes
    global API_PACKAGES_LIST, API_CLASSES_LIST, API_SYSTEM_COMMANDS

    ############################################################
    # READING PACKAGES, CLASSES AND SYSTEM COMMANDS
    ############################################################
    package_file = load_file(str(package_index_file))
    API_PACKAGES_LIST = [x.strip() for x in package_file]

    class_file = load_file(str(classes_index_file))
    API_CLASSES_LIST = [x.strip() for x in class_file]

    system_commands_file = load_file(str(system_commands_file))
    API_SYSTEM_COMMANDS = [x.strip() for x in system_commands_file]
    ############################################################

    ############################################################
    # BUILDING LIST OF APKS
    ############################################################
    apk_list = list_files(source_directory, '*.apk')
    print '[*] Number of APKs:', len(apk_list)
    ############################################################

    ############################################################
    # ANALYSING APKS
    ############################################################
    database = collections.OrderedDict()
    print "ANALYSING APKS..."
    for analyze_apk in tqdm(apk_list):

        # Getting the name of the folder that contains all apks and folders with apks
        base_folder = source_directory.split("/")[-1]

        apk_filename = join_dir(base_folder, analyze_apk.replace(source_directory, ''))
        apk_filename = apk_filename.replace("//", "/")

        apk_name_no_extensions = "".join(apk_filename.split("/")[-1].split(".")[:-1])

        if os.path.isfile(join_dir(output_folder, apk_filename.split("/")[-1].replace('.apk', '-analysis.json'))):
            database[apk_filename.replace('.apk', '')] = json.load(open(join_dir(output_folder, apk_filename.split("/")[-1].
                                                                            replace('.apk', '-analysis.json'))))
            continue

        pre_static_dict = collections.OrderedDict()

        pre_static_dict['Filename'] = apk_filename

        hasher_md5 = hashlib.md5()
        hasher_sha256 = hashlib.sha256()
        hasher_sha1 = hashlib.sha1()
        with open(analyze_apk, 'rb') as afile:
            buf = afile.read()
            hasher_md5.update(buf)
            hasher_sha256.update(buf)
            hasher_sha1.update(buf)

        md5 = hasher_md5.hexdigest()
        sha256 = hasher_sha256.hexdigest()
        sha1 = hasher_sha1.hexdigest()

        pre_static_dict["md5"] = md5
        pre_static_dict["sha256"] = sha256
        pre_static_dict["sha1"] = sha1

        """
        if label is not None:
            pre_static_dict["Label"] = label
        else:
            pre_static_dict["Label"] = "/".join(apk_filename.split("/")[:-1])
        """
        pre_static_dict["VT_positives"] = None

        try:
            androguard_apk_object = apk.APK(analyze_apk)
        except Exception:
            print "ERROR in APK: " + apk_name_no_extensions
            continue

        static_analysis_dict = collections.OrderedDict()
        # Package name
        static_analysis_dict['Package name'] = androguard_apk_object.get_package()

        # Permissions
        static_analysis_dict['Permissions'] = androguard_apk_object.get_permissions()

        # Opcodes
        static_analysis_dict['Opcodes'] = opcodes_analysis(androguard_apk_object)

        # Activities
        try:
            list_activities = androguard_apk_object.get_activities()
        except UnicodeEncodeError:
            list_activities = []

        # Main activity
        static_analysis_dict['Main activity'] = androguard_apk_object.get_main_activity()

        # Receivers
        try:
            list_receivers = androguard_apk_object.get_receivers()
        except UnicodeEncodeError:
            list_receivers = []

        # Services
        try:
            list_services = androguard_apk_object.get_services()
        except UnicodeEncodeError:
            list_services = []

        # API calls and Strings
        list_smali_api_calls, list_smali_strings = read_strings_and_apicalls(analyze_apk, API_PACKAGES_LIST,
                                                                             API_CLASSES_LIST)
        for api_call in list_smali_api_calls.keys():
            new_api_call = '.'.join(api_call.split(".")[:-1])
            if new_api_call in list_smali_api_calls.keys():
                list_smali_api_calls[new_api_call] = list_smali_api_calls[new_api_call] + list_smali_api_calls[api_call]
            else:
                list_smali_api_calls[new_api_call] = list_smali_api_calls[api_call]
                del list_smali_api_calls[api_call]
        static_analysis_dict['API calls'] = list_smali_api_calls
        static_analysis_dict['Strings'] = Counter(filter(None, list_smali_strings))

        # API packages

        API_packages_dict = collections.OrderedDict()
        android_list_packages_lenghts = [len(x.split(".")) for x in API_PACKAGES_LIST]

        list_api_calls_keys = list_smali_api_calls.keys()
        for api_call in list_api_calls_keys:
            score = 0
            package_chosen = None
            for i, package in enumerate(API_PACKAGES_LIST):
                len_package = android_list_packages_lenghts[i]
                if api_call.startswith(package) and len_package > score:
                    score = len_package
                    package_chosen = package
            if package_chosen is not None:
                if not package_chosen in API_packages_dict.keys():
                    API_packages_dict[package_chosen] = list_smali_api_calls[api_call]
                else:
                    API_packages_dict[package_chosen] += list_smali_api_calls[api_call]

        static_analysis_dict['API packages'] = API_packages_dict
        

        # System commands
        list_system_commands = read_system_commands(list_smali_strings, API_SYSTEM_COMMANDS)
        static_analysis_dict['System commands'] = Counter(list_system_commands)

        # Intents
        try:
            static_analysis_dict['Intents'] = intents_analysis(join_dir(analyze_apk.replace('.apk', ''),
                                                                        'AndroidManifest.xml'))
        except:
            static_analysis_dict['Intents'] = {'Failed to extract intents': 0}

        # Intents of activities
        intents_activities = collections.OrderedDict()
        for activity in list_activities:

            
            intents_activities[activity] = check_for_intents(join_dir(analyze_apk.replace('.apk', ''),
                                                                      'AndroidManifest.xml'),
                                                             activity, 'activity')
        static_analysis_dict['Activities'] = intents_activities

        # Intents of services
        intents_services = collections.OrderedDict()
        for service in list_services:
            intents_services[service] = check_for_intents(join_dir(analyze_apk.replace('.apk', ''),
                                                                   'AndroidManifest.xml'),
                                                          service, 'service')
        static_analysis_dict['Services'] = intents_services

        # Intents of receivers
        intents_receivers = collections.OrderedDict()
        for intent in list_receivers:
            intents_receivers[intent] = check_for_intents(join_dir(analyze_apk.replace('.apk', '/'),
                                                                   'AndroidManifest.xml'),
                                                          intent, 'receiver')
        static_analysis_dict['Receivers'] = intents_receivers

        if not noclean_up:
            cleanup(analyze_apk)

        ############################################################
        # READING DYNAMIC ANALYSIS FILES TO INCLUDE IN JSON
        # ONLY THE NAME OF THE FILE IS INCLUDED
        # TODO EACH FILE MUST BE STORED IN A FOLDER NAMED AS THE TOOL USED
        ############################################################
        dynamic_analysis_dict = collections.OrderedDict()

        if dynamic_analysis_folder and isdir(dynamic_analysis_folder):
            dynamic_analysis_folders = [join_dir(dynamic_analysis_folder, x) for x in listdir(str(dynamic_analysis_folder)) if
                                        isdir(join_dir(dynamic_analysis_folder, x))]

            for dynamic_analysis_tool_folder in dynamic_analysis_folders:
                # dynamic_analysis_folder += "/"

                path_to_folder = dynamic_analysis_tool_folder.split("/")
                dynamic_tool_name = filter(None, path_to_folder)[-1]
                for extension in POSSIBLE_DYNAMIC_FILES_EXTENSIONS:
                    if os.path.isfile(join_dir(dynamic_analysis_tool_folder, apk_name_no_extensions + extension)):

                        dynamic_file_name = join_dir(dynamic_analysis_tool_folder, apk_name_no_extensions + extension)

                        # If the file has .json extension, it is added to the global json
                        # If not, the field is filled with the path to the dynamic analysis file
                        if extension == ".json":
                            dynamic_analysis_dict[dynamic_tool_name] = json.load(open(dynamic_file_name))
                        else:
                            dynamic_analysis_dict[dynamic_tool_name] = dynamic_file_name

                        break
        ############################################################
        # READING FLOWDROID ANALYSIS FILES TO INCLUDE IN JSON
        # ONLY THE NAME OF THE FILE IS INCLUDED
        # TODO EACH FILE MUST BE STORED IN A FOLDER NAMED AS THE TOOL USED
        ############################################################
        flowdroid_file = ""
        if flowdroid_folder:

            if isfile(join_dir(flowdroid_folder, apk_name_no_extensions + ".csv")):
                flowdroid_file = join_dir(flowdroid_folder, apk_name_no_extensions + ".csv")
                # static_analysis_dict['FlowDroid'] = flowdroid_field

                data_flowdroid_csv = pd.read_csv(flowdroid_file)

                # Setting column names with the first column
                data_flowdroid_csv.index = data_flowdroid_csv["Sources\\Sinks"]
                if "Sources\\Sinks" in data_flowdroid_csv.columns:        
                    del data_flowdroid_csv["Sources\\Sinks"]

                flowdroid_field = data_flowdroid_csv.to_dict()
                static_analysis_dict['FlowDroid'] = flowdroid_field

        ############################################################
        # READING VIRUSTOTAL FILE TO INCLUDE IN JSON
        ############################################################

        virus_total_dict = collections.OrderedDict()
        if virus_total_reports_folder:
            vt_file_name = join_dir(virus_total_reports_folder, apk_name_no_extensions + ".json")
            if isfile(vt_file_name):
                load_vt_json = load_from_json(vt_file_name)
                virus_total_dict = load_vt_json

                # Saving number of antivirus engines from VirusTotal testing for positive in the pre static section
                pre_static_dict["VT_positives"] = load_vt_json["positives"]
                pre_static_dict["VT_engines"] = len(load_vt_json["scans"].keys())
            else:
                virus_total_dict = ""

        

        ############################################################
        # GETTING AVCLASS LABEL IF VIRUSTOTAL ANALYSIS IS AVAILABLE
        ############################################################

        if virus_total_reports_folder and avclass:
            vt_file_name = join_dir(virus_total_reports_folder, apk_name_no_extensions + ".json")
            if isfile(vt_file_name):
                pre_static_dict["avclass"] = get_avclass_label(vt_file_name)

        ############################################################
        # FILLING APK JSON FIELD
        ############################################################
        apk_total_analysis = OrderedDict([("Pre_static_analysis", pre_static_dict),
                                          ("Static_analysis", static_analysis_dict),
                                          ("Dynamic_analysis", dynamic_analysis_dict),
                                          ("VirusTotal", virus_total_dict)])

        database[apk_filename.replace('.apk', '').replace('.', '-')] = apk_total_analysis

        ############################################################
        # SAVING ANALYSIS FOR INDIVIDUAL APK WHEN SELECTED
        ############################################################
        if single_analysis:
            # save_single_analysis(join_dir(output_folder, apk_filename.split("/")[-1].
            # replace('.apk', '-analysis.json')),
            #                     apk_total_analysis)

            save_as_json(apk_total_analysis, output_name=join_dir(output_folder, apk_name_no_extensions +
                                                                  "-analysis.json"))

    save_as_json(database, output_name=join_dir(output_folder, OUTPUT_FILE_GLOBAL_JSON))

    ############################################################
    # EXPORTING TO MONGODB
    ############################################################
    if export_mongodb is not None:
        client = MongoClient('mongodb://' + export_mongodb)
        # Creating database
        db = client['AndroPyTool_database']
        coll = db['report_' + TIME_EXECUTION]

        for apk_key in database.keys():
            
            for call in database[apk_key]["Static_analysis"]["API calls"].keys():
                database[apk_key]["Static_analysis"]["API calls"][call.replace(".", "-")] = \
                    database[apk_key]["Static_analysis"]["API calls"][call]
                del database[apk_key]["Static_analysis"]["API calls"][call]
            
            for string in database[apk_key]["Static_analysis"]["Strings"].keys():
                database[apk_key]["Static_analysis"]["Strings"][string.replace(".", "-").replace("$", "U+FF04")] = \
                    database[apk_key]["Static_analysis"]["Strings"][string]
                del database[apk_key]["Static_analysis"]["Strings"][string]
                
            for activity in database[apk_key]["Static_analysis"]["Activities"].keys():
                database[apk_key]["Static_analysis"]["Activities"][activity.replace(".", "-")] = \
                    database[apk_key]["Static_analysis"]["Activities"][activity]
                del database[apk_key]["Static_analysis"]["Activities"][activity]

            for receiver in database[apk_key]["Static_analysis"]["Receivers"].keys():
                database[apk_key]["Static_analysis"]["Receivers"][receiver.replace(".", "-")] = \
                    database[apk_key]["Static_analysis"]["Receivers"][receiver]
                del database[apk_key]["Static_analysis"]["Receivers"][receiver]

            for intent in database[apk_key]["Static_analysis"]["Intents"].keys():
                database[apk_key]["Static_analysis"]["Intents"][intent.replace(".", "-")] = \
                    database[apk_key]["Static_analysis"]["Intents"][intent]
                del database[apk_key]["Static_analysis"]["Intents"][intent]

            for package in database[apk_key]["Static_analysis"]["API packages"].keys():
                database[apk_key]["Static_analysis"]["API packages"][package.replace(".", "-")] = \
                    database[apk_key]["Static_analysis"]["API packages"][package]
                del database[apk_key]["Static_analysis"]["API packages"][package]
            
            for service in database[apk_key]["Static_analysis"]["Services"].keys():
                database[apk_key]["Static_analysis"]["Services"][service.replace(".", "-")] = \
                    database[apk_key]["Static_analysis"]["Services"][service]
                del database[apk_key]["Static_analysis"]["Services"][service]

            coll.insert_one(database[apk_key]["Static_analysis"]).inserted_id

    ############################################################
    # EXPORTING TO CSV
    ############################################################
    if export_csv is not None:
        set_permissions = set()
        set_opcodes = set()
        set_apicalls = set()
        set_systemcommands = set()
        set_intents_activities = set()
        set_intents_services = set()
        set_intents_receivers = set()
        set_api_packages = set()

        for apk_key in tqdm(database.keys()):
            apk_dict = database[apk_key]
            
            if len(apk_key.split("/")) > 1:
                kind = apk_key.split("/")[0]
                hash_app = apk_key.split("/")[1]
            else:
                kind = ""
                hash_app = apk_key

            set_permissions.update(apk_dict["Static_analysis"]["Permissions"])
            set_opcodes.update(apk_dict["Static_analysis"]["Opcodes"])
            set_apicalls.update(apk_dict["Static_analysis"]["API calls"])
            set_systemcommands.update(apk_dict["Static_analysis"]["System commands"])
            
            for activity in apk_dict["Static_analysis"]["Activities"]:
                if apk_dict["Static_analysis"]["Activities"][activity] is not None and \
                    len(apk_dict["Static_analysis"]["Activities"][activity]) > 0:
                    set_intents_activities.update(apk_dict["Static_analysis"]["Activities"][activity])

            for service in apk_dict["Static_analysis"]["Services"]:
                if apk_dict["Static_analysis"]["Services"][service] is not None and \
                    len(apk_dict["Static_analysis"]["Services"][service]) > 0:
                    set_intents_services.update(apk_dict["Static_analysis"]["Services"][service])

            for receiver in apk_dict["Static_analysis"]["Receivers"]:
                if apk_dict["Static_analysis"]["Receivers"][receiver] is not None and \
                    len(apk_dict["Static_analysis"]["Receivers"][receiver]) > 0:
                    set_intents_receivers.update(apk_dict["Static_analysis"]["Receivers"][receiver])

            set_api_packages.update(apk_dict["Static_analysis"]["API packages"])

        list_permissions = [x.replace(" ", "") for x in list(set_permissions)]
        list_opcodes = list(set_opcodes)
        list_apicalls = list(set_apicalls)
        list_systemcommands = list(set_systemcommands)
        list_intents_activities = list(set_intents_activities)
        list_intents_services = list(set_intents_services)
        list_intents_receivers = list(set_intents_receivers)
        list_api_packages = list(set_api_packages)

        for i, apicall in enumerate(list(list_apicalls)):
            list_apicalls[i] = ".".join(apicall.encode('ascii', 'ignore').split(".")[:-1])

        list_apicalls = list(set(list_apicalls))

        list_rows = []

        rows_permissions = []
        rows_opcodes = []
        rows_apicalls = []
        rows_systemcommands = []
        rows_intents_activities = []
        rows_intents_services = []
        rows_intents_receivers = []
        rows_api_packages = []
                
        for apk_key in tqdm(database.keys()):
            apk_dict = database[apk_key]
            label = None
            if len(apk_key.split("/")) > 1:
                label = apk_key.split("/")[0]
                hash_app = apk_key.split("/")[1]
            else:
                label = ""
                hash_app = apk_key
            
            list_permissions_filled = [0 for x in range(len(list_permissions))]
            for i, item in enumerate(list_permissions):
                if item.replace(" ", "") in apk_dict["Static_analysis"]["Permissions"]:
                    list_permissions_filled[i] = 1

            list_opcodes_filled = [0 for x in range(len(list_opcodes))]
            for i, item in enumerate(list_opcodes):
                if item in apk_dict["Static_analysis"]["Opcodes"]:
                    list_opcodes_filled[i] = apk_dict["Static_analysis"]["Opcodes"][item]

            list_apicalls_filled = [0 for x in range(len(list_apicalls))]
            for i, item in enumerate(list_apicalls):
                if item in apk_dict["Static_analysis"]["API calls"]:
                    list_apicalls_filled[i] = apk_dict["Static_analysis"]["API calls"][item]

            list_systemcommands_filled = [0 for x in range(len(list_systemcommands))]
            for i, item in enumerate(list_systemcommands):
                if item in apk_dict["Static_analysis"]["System commands"]:
                    list_systemcommands_filled[i] = apk_dict["Static_analysis"]["System commands"][item]

            list_intents_activities_filled = [0 for x in range(len(list_intents_activities))]
            for i, item in enumerate(list_intents_activities):
                if item in apk_dict["Static_analysis"]["Activities"]:
                    list_intents_activities_filled[i] = 1

            list_intents_services_filled = [0 for x in range(len(list_intents_services))]
            for i, item in enumerate(list_intents_services):
                if item in apk_dict["Static_analysis"]["Services"]:
                    list_intents_services_filled[i] = 1

            list_intents_receivers_filled = [0 for x in range(len(list_intents_receivers))]
            for i, item in enumerate(list_intents_receivers):
                if item in apk_dict["Static_analysis"]["Receivers"]:
                    list_intents_receivers_filled[i] = 1

            list_api_packages_filled = [0 for x in range(len(list_api_packages))]
            print list_api_packages
            for i, item in enumerate(list_api_packages):
                if item in apk_dict["Static_analysis"]["API packages"]:
                    list_intents_receivers_filled[i] = 1

            complete_row = [label] + list_permissions_filled + list_opcodes_filled + list_apicalls_filled + \
                        list_systemcommands_filled + list_intents_activities_filled + \
                        list_intents_services_filled + list_intents_receivers_filled + list_api_packages_filled

            rows_permissions.append(list_permissions_filled)
            rows_opcodes.append(list_opcodes_filled)
            rows_apicalls.append(list_apicalls_filled)
            rows_systemcommands.append(list_systemcommands_filled)
            rows_intents_activities.append(list_intents_activities_filled)
            rows_intents_services.append(list_intents_services_filled)
            rows_intents_receivers.append(list_intents_receivers_filled)
            rows_api_packages.append(list_api_packages_filled)
            list_rows.append(complete_row)

        list_permissions = ["PERMISSION-" + x for x in list(list_permissions)]
        list_opcodes = ["OPCODE-" + x for x in list(list_opcodes)]
        list_apicalls = ["APICALL-" + x for x in list(list_apicalls)]
        list_systemcommands = ["SYSTEMCOMMAND-" + x for x in list(list_systemcommands)]
        list_intents_activities = ["ACTIVITY-" + x for x in list(list_intents_activities)]
        list_intents_services = ["SERVICE-" + x for x in list(list_intents_services)]
        list_intents_receivers = ["RECEIVER-" + x for x in list(list_intents_receivers)]
        list_api_packages = ["APIPACKAGE-" + x for x in list(list_api_packages)]

        complete_list_fields = ["label"] + list_permissions + list_opcodes + list_apicalls + \
                       list_systemcommands + list_intents_activities + list_intents_services + list_intents_receivers + \
                       list_api_packages

        with open(output_folder + "/" +  export_csv, 'wb') as csv_file:

            csvwriter = csv.writer(csv_file, delimiter=",")
            csvwriter.writerow(complete_list_fields)
            print "WRITING CSV FILE..."
            for row in tqdm(list_rows):
                csvwriter.writerow(row)

if __name__ == '__main__':
    main()

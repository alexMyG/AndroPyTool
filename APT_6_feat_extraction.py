import sys
import csv
import time
import bson
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


############################################################
# VARIABLES
############################################################
TIME_EXECUTION = str(time.time())
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

    parser.add_argument('-c', '--cleanup', default=True,
                        help='Perform cleanup deleting temporary working files. Default: True', action='store_false')

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
                       clean_up=args.cleanup, flowdroid_folder=args.FlowDroid, package_index_file=args.Package,
                       classes_index_file=args.Class, system_commands_file=args.SystemC, label=args.label,
                       avclass=args.AVClass, export_mongodb=args.mongodbURI, export_csv=args.exportCSV)


############################################################


############################################################
# MAIN METHOD
############################################################
def features_extractor(apks_directory, single_analysis, dynamic_analysis_folder, virus_total_reports_folder,
                       flowdroid_folder, output_folder, clean_up, package_index_file, classes_index_file,
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
    :param clean_up: If unnecesary files generated are removed
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

        if label is not None:
            pre_static_dict["Label"] = label
        else:
            pre_static_dict["Label"] = "/".join(apk_filename.split("/")[:-1])

        androguard_apk_object = apk.APK(analyze_apk)

        static_analysis_dict = collections.OrderedDict()
        # Package name
        static_analysis_dict['Package name'] = androguard_apk_object.get_package()

        # Permissions
        static_analysis_dict['Permissions'] = androguard_apk_object.get_permissions()

        # Opcodes
        static_analysis_dict['Opcodes'] = opcodes_analysis(androguard_apk_object)

        # Activities
        list_activities = androguard_apk_object.get_activities()

        # Main activity
        static_analysis_dict['Main activity'] = androguard_apk_object.get_main_activity()

        # Receivers
        list_receivers = androguard_apk_object.get_receivers()

        # Services
        list_services = androguard_apk_object.get_services()

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

        if clean_up:
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
                        dynamic_analysis_dict[dynamic_tool_name] = join_dir(dynamic_analysis_tool_folder,
                                                                            apk_name_no_extensions + extension)
                        break
        ############################################################
        # READING FLOWDROID ANALYSIS FILES TO INCLUDE IN JSON
        # ONLY THE NAME OF THE FILE IS INCLUDED
        # TODO EACH FILE MUST BE STORED IN A FOLDER NAMED AS THE TOOL USED
        ############################################################
        flowdroid_field = ""
        if flowdroid_folder:

            if isfile(join_dir(flowdroid_folder, apk_name_no_extensions + ".csv")):
                flowdroid_field = join_dir(flowdroid_folder, apk_name_no_extensions + ".csv")
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

        database[apk_filename.replace('.apk', '')] = apk_total_analysis

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
        for apk_key in database.keys():
            for call in database[apk_key]["Static_analysis"]["API calls"].keys():
                database[apk_key]["Static_analysis"]["API calls"][call.replace(".", "-")] = \
                    database[apk_key]["Static_analysis"]["API calls"][call]
                del database[apk_key]["Static_analysis"]["API calls"][call]

            for string in database[apk_key]["Static_analysis"]["Strings"].keys():
                database[apk_key]["Static_analysis"]["Strings"][string.replace(".", "-")] = \
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

        client = MongoClient('mongodb://' + export_mongodb)
        # Creating database
        db = client['AndroPyTool_database']

        coll = db['report_' + TIME_EXECUTION]

        coll.insert_one(database).inserted_id

        # CSV

    ############################################################
    # EXPORTING TO CSV
    ############################################################
    if export_csv is not None:
        with open('dict.csv', 'wb') as csv_file:

            # FlowDroid and Dynamic analysis fields are not included into the CSV since they only report the path to the
            # related report, so it cannot be considered as a feature

            list_apks = database.keys()

            list_fields = database[list_apks[0]]["Pre_static_analysis"].keys()
            list_fields += ["Package name"]
            list_fields += ["Main activity"]

            sub_fields_static_analysis = ["Permissions", "Opcodes", "API calls", "API packages", "Strings", "System commands", "Intents",
                                          "Activities", "Services", "Receivers"]

            dict_subfields = {}
            # Here, each subfield of the static analysis field is included into the list
            for apk_id in list_apks:
                for sub_field in sub_fields_static_analysis:
                    list_fields += database[apk_id]["Static_analysis"][sub_field]

                    dict_subfields[sub_field] = database[apk_id]["Static_analysis"][sub_field]

            writer = csv.DictWriter(csv_file, fieldnames=list_fields)
            writer.writeheader()

            for apk_id in list_apks:
                apk_dict = {}
                apk_dict.update(database[apk_id]["Pre_static_analysis"])

                # Adding fields from static analysis
                apk_dict.update({"Package name": database[apk_id]["Static_analysis"]["Package name"],
                                 "Main activity": database[apk_id]["Static_analysis"]["Main activity"]})

                sub_dict = {}
                for sub_field in sub_fields_static_analysis:
                    for value in dict_subfields[sub_field]:
                        if value in database[apk_id]["Static_analysis"][sub_field]:
                            sub_dict[value] = 1
                        else:
                            sub_dict[value] = 0

                apk_dict.update(sub_dict)
                writer.writerow(apk_dict)


if __name__ == '__main__':
    main()

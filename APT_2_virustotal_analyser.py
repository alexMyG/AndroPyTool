import sys
import time
import shutil
import urllib
import os.path
import hashlib
import urllib2
import requests
import argparse
import simplejson

from tqdm import *
from os import listdir
from termcolor import colored
from os.path import isfile, join
from simplejson import JSONDecodeError
from argparse import RawTextHelpFormatter
from os.path import join as join_dir

# TODO CHECK WHAT HAPPENS WHEN AN ANALYSIS HAS NOT BEEN FOUND OR WHEN IT COULD NOT BE DOWNLOADED

os.path.dirname(os.path.abspath(__file__))

VT_ANALYSIS_DIRECTORY_NAME = "/../VT_ANALYSIS/"

VT_KEY = None


def print_message(message, with_color, color):
    if with_color:
        print colored(message, color)
    else:
        print message


def sha256(fname):
    """
    Method to calculate the SHA256 hash of a file
    :param fname: Path to file
    :return: SHA256 of the input file
    """
    hash_num = hashlib.sha256()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_num.update(chunk)
    return hash_num.hexdigest()


def get_report_hash(hash_num):
    """
    Calls the VirusTotal service with a specific hash
    :param hash_num: Hash of the app whose VirusTotal report is required
    :return: VirusTotal report in JSON format
    """
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": hash_num, "apikey": VT_KEY}

    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)

    try:
        response = urllib2.urlopen(req)
    except urllib2.URLError:
        return ""

    json = response.read()

    return json


def main():
    parser = argparse.ArgumentParser(
        description="Script designed for analysing apks with the VirusTotal service\n\n" +
                    '[!] A VirusTotal API key must be provided in a file called vt_key inside '
                    'the info/directory',
        formatter_class=RawTextHelpFormatter)

    parser.add_argument('-s', '--source', help='Source directory for APKs', required=True)

    parser.add_argument('-o', '--output', help='Output directory for VirusTotal Analysis', required=False)

    parser.add_argument('-so', '--samplesoutput', help='Output directory to move APKs after analysis', required=False)
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    analyse_virustotal(args.source, vt_analysis_output_folder=args.output, output_samples_folder=args.samplesoutput,
                       with_color=True)


def analyse_virustotal(source_directory, vt_api_key, vt_analysis_output_folder=None, output_samples_folder=None,
                       with_color=True):
    """
    Analyses a set of APK files with the VirusTotal service

    Parameters
    ----------
    :param source_directory: Folder containing apk files
    :param vt_analysis_output_folder: Folder where VirusTotal reports are saved
    :param output_samples_folder:  Folder where apk files are saved after analysed with VirusTotal
    :return:
    """
    if len(vt_api_key) != 64:
        print 'ERROR! - invalid vt_key file. Please, provide a virustotal key!'
        sys.exit(0)

    global VT_KEY
    VT_KEY = vt_api_key

    if vt_analysis_output_folder is None:
        vt_analysis_output_folder = join_dir(source_directory, VT_ANALYSIS_DIRECTORY_NAME)

    reports_not_received = 0

    # TODO It is necessary to control when the directory could not be created (for instance if the folder is going to be
    # TODO created in a non existing directory

    if not os.path.exists(vt_analysis_output_folder):
        os.makedirs(vt_analysis_output_folder)

    if output_samples_folder is not None:
        if not os.path.exists(output_samples_folder):
            os.makedirs(output_samples_folder)

    apks_found = [f for f in listdir(source_directory) if isfile(join(source_directory, f))
                  and f.endswith(".apk")]

    count_positives = 0

    for apk in tqdm(apks_found):

        if isfile(join(source_directory, apk.replace(".apk", ".json"))):
            print_message("APK WITH JSON. CONTINUE...", with_color, 'green')
            continue
        apk_path = source_directory + apk
        hash_sha = sha256(apk_path)
        report = ""
        while report == "":
            report = get_report_hash(hash_sha)
            if report == "":
                print_message("No report received. Waiting...", with_color, 'red')
                time.sleep(1)

        response_dict = simplejson.loads(report)

        response_code = response_dict.get("response_code")
        if response_code == 1:  # Report generated
            positives = response_dict.get("positives")
            file_json = open(apk_path.replace(".apk", "") + ".json", "w")
            file_json.write(report)
            if positives > 0:
                count_positives += 1

            shutil.move(apk_path.replace(".apk", "") + ".json",
                        join_dir(vt_analysis_output_folder, apk.replace(".apk", "") + ".json"))
            if output_samples_folder is not None:
                shutil.move(join_dir(source_directory, apk), join_dir(output_samples_folder, apk))

        if response_code == 0:
            reports_not_received += 1

            params = {'apikey': VT_KEY}
            files = {'file': ("apk", open(apk_path, 'rb'))}
            print "Uploading APK: " + apk
            print "File not analysed yet. Uploading file..."
            try:
                response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)

            except requests.exceptions.ConnectionError:
                print_message("Connection error", with_color, 'red')
                continue
            print str(response)
            try:
                response.json()
            except JSONDecodeError:
                print_message("JSONDecodeError", with_color, 'red')
                continue
            print_message("SENT TO VIRUS-TOTAL", with_color, 'blue')

    if reports_not_received > 0:
        print "WARNING! " + str(reports_not_received) + " apks does not have yet a VT analysis. Please" \
                                                         ", execute again this script after a while"
    else:
        print_message("SUCCESS!!", with_color, 'green')
        print " All reports have been saved in the VT_ANALYSIS folder. APKS are in SAMPLES folder."


if __name__ == '__main__':
    main()

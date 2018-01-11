import os
import sys
import json
import shutil
import os.path
import argparse

from tqdm import *
from os import listdir
from termcolor import colored
from os.path import isfile, join
from os.path import join as join_dir
from argparse import RawTextHelpFormatter

BW_DIRECTORY_NAME = "BW/"
MW_DIRECTORY_NAME = "MW/"


def main():
    parser = argparse.ArgumentParser(
        description=colored("Script designed for filtering benign and malware APKs based on their VirusTotal analysis"
                            "\n\n", "green"),
        formatter_class=RawTextHelpFormatter)

    parser.add_argument('-s', '--source', help='Source directory for APKs', required=True)

    parser.add_argument('-vt', '--vtanalysis', help='Directory containing VirusTotal analysis in JSON', required=False)

    parser.add_argument('-bw', '--bwoutput', help='Output directory for benign APKs', required=False)

    parser.add_argument('-mw', '--mwoutput', help='Output directory for malicious APKs', required=False)

    parser.add_argument('-t', '--threshold', help='Number of positives from AV engines needed to categorise as'
                                                  ' malware. Default 1',
                        required=False)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    filter_apks(source_directory=args.source,
                vt_analysis_directory=args.vtanalysis,
                bw_directory_name=args.bwoutput,
                mw_directory_name=args.mwoutput,
                threshold=args.threshold)


def filter_apks(source_directory, vt_analysis_directory, bw_directory_name=None, mw_directory_name=None,
                threshold=1):
    """
    Filter apks between malware and benignware based on the report received from VirusTotal

    Parameters
    ----------
    :param source_directory: Folder containing apk files
    :param vt_analysis_directory: Folder containing reports received from VirusTotal
    :param bw_directory_name: Folder where benignware applications are moved to
    :param mw_directory_name: Folder where malware applications are moved to
    :param threshold: Minimum number of antivirus testing for positive to consider a sample as malicious. Default: 1
    :return:
    """

    files_apks = [f for f in listdir(source_directory) if isfile(join(source_directory, f)) and f.endswith(".apk")]

    if bw_directory_name is None:
        bw_directory_name = join_dir(source_directory, BW_DIRECTORY_NAME)

    if mw_directory_name is None:
        mw_directory_name = join_dir(source_directory, MW_DIRECTORY_NAME)

    if not os.path.exists(bw_directory_name):
        os.makedirs(bw_directory_name)

    if not os.path.exists(mw_directory_name):
        os.makedirs(mw_directory_name)

    for apk in tqdm(files_apks):
        app_id = apk.replace(".apk", "")
        json_id = join_dir(vt_analysis_directory, app_id + ".json")
        apk_path = join_dir(source_directory, apk)

        if not os.path.isfile(json_id):
            print colored('ERROR! ', 'red') + "NO VT ANALYSIS FOUND FOR APK: " + app_id
            continue

        data_file = open(json_id)

        try:
            data = json.load(data_file)
        except ValueError:
            continue

        positives = data["positives"]

        if positives < threshold:
            shutil.move(apk_path, join_dir(bw_directory_name, apk))

        if positives >= threshold:
            shutil.move(apk_path, join_dir(mw_directory_name, apk))


if __name__ == '__main__':
    main()

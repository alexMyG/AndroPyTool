import sys
import os
import shutil
import argparse
from tqdm import *
from os import listdir
from termcolor import colored
from os.path import join as join_dir
from os.path import isfile, join, isdir
from argparse import RawTextHelpFormatter
from androguard.core.bytecodes.apk import APK

# VARIABLES
NUMBER_ARGUMENTS = 2
VALID_APKS_DIRECTORY = "samples/"
INVALID_APKS_DIRECTORY = "invalid_apks/"


def main():

    parser = argparse.ArgumentParser(
        description=colored("Script designed for filtering invalid apks\n\n", "green") +
                            "[!] Each apk in the source directory is checked "
                            "with AndroGuard in order to check if the apk is valid or not. ",
        formatter_class=RawTextHelpFormatter)

    parser.add_argument('-s', '--source', help='Source directory for APKs', required=True)

    parser.add_argument('-o', '--output', help='Output directory for valid APKs', required=False)

    parser.add_argument('-inv', '--invalid', help='Output directory for invalid APKs', required=False)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    # CHECKING ARGUMENTS:
    files_apks = [f for f in listdir(args.source) if isfile(join(args.source, f)) and f.endswith(".apk")]
    if len(files_apks) == 0:
        print colored("ERROR! - ", "red") + "Folder without apk files! The source directory must contain a number of " \
                                            "apk files."
        sys.exit(0)

    filter_valid_apks(args.source, valid_apks_directory=args.output, invalid_apks_directory=args.invalid)


def filter_valid_apks(source_directory, valid_apks_directory=None, invalid_apks_directory=None):
    """
    Analyses a set of Android apks with Androguard to filter valid and invalid samples
    If a JSON file with the same name that the app is found in the source directory, it is also moved

    Parameters
    ----------
    :param source_directory: Folder containing apk files
    :param valid_apks_directory: Folder where valid apks are saved
    :param invalid_apks_directory: Folder where invalid apks are saved
    """
    if not isdir(source_directory):
        print "Folder not found!"
        sys.exit(0)

    if valid_apks_directory is None:
        valid_apks_directory = join_dir(source_directory, VALID_APKS_DIRECTORY)

    if invalid_apks_directory is None:
        invalid_apks_directory = join_dir(source_directory, INVALID_APKS_DIRECTORY)

    num_valid_apk = 0
    num_invalid_apk = 0

    files_apks = [f for f in listdir(source_directory) if isfile(join(source_directory, f)) and f.endswith(".apk")]

    print str(len(files_apks)) + " apks found. Processing..."

    if not os.path.exists(valid_apks_directory):
        os.makedirs(valid_apks_directory)

    if not os.path.exists(invalid_apks_directory):
        os.makedirs(invalid_apks_directory)

    for apk in tqdm(files_apks):

        if not apk.endswith(".apk"):
            shutil.move(join_dir(source_directory, apk), join_dir(source_directory, apk + ".apk"))
            apk += ".apk"

        json_file = apk.replace(".apk", ".json")
        try:
            apk_analysed = APK(join_dir(source_directory, apk))
            valid_apk = apk_analysed.valid_apk

        except:
            valid_apk = False

        if valid_apk:

            if isfile(join(source_directory, json_file)):
                shutil.move(join_dir(source_directory, json_file), join_dir(valid_apks_directory, json_file))

            shutil.move(join_dir(source_directory, apk), join_dir(valid_apks_directory, apk))
            num_valid_apk += 1
        else:
            if isfile(join(source_directory, json_file)):
                shutil.move(join_dir(source_directory, json_file), join_dir(invalid_apks_directory, json_file))
            shutil.move(join_dir(source_directory, apk), join_dir(invalid_apks_directory, apk))
            num_invalid_apk += 1

    print colored("TOTAL VALID APKS: " + str(num_valid_apk), "green")
    print colored("TOTAL INVALID APKS: " + str(num_invalid_apk), "red")


if __name__ == '__main__':
    main()

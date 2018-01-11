import os
import sys
import argparse

from StringIO import StringIO  # Python2

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'avclass', 'lib/'))
from avclass.avclass_labeler import main as avclass_labeler


# READING JSON FILES

def get_avclass_label(path_vt_file):

    argparser = argparse.ArgumentParser()
    argparser.add_argument('-vt', type=str)
    argparser.add_argument('-hash')
    argparser.add_argument('-gt')
    argparser.add_argument('-gen')
    argparser.add_argument('-alias')
    argparser.add_argument('-av')
    argparser.add_argument('-lb')
    argparser.add_argument('-lbdir')
    argparser.add_argument('-verbose')
    argparser.add_argument('-gendetect')
    argparser.add_argument('-aliasdetect')
    argparser.add_argument('-pup')
    argparser.add_argument('-fam')
    argparser.add_argument('-vtdir')

    # We need this in order to avoid errors due to parsing the former arguments
    args, unknown = argparser.parse_known_args()

    args.vt = [path_vt_file]
    old_stdout = sys.stdout
    result = StringIO()
    sys.stdout = result
    save_stderr = sys.stderr
    sys.stderr = open(os.devnull, 'w')

    avclass_labeler(args)

    sys.stderr = save_stderr
    sys.stdout = old_stdout

    result_string = result.getvalue()

    return result_string.split()[1]
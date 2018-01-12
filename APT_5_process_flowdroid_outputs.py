import re
import os
import csv
import sys
import argparse

from tqdm import tqdm
from termcolor import colored
from argparse import RawTextHelpFormatter


PRM_DOMAINS = 'info/prmDomains.txt'


def print_message(message, with_color, color):
    if with_color:
        print colored(message, color)
    else:
        print message


def main():
    parser = argparse.ArgumentParser(
        description="- Script designed for processing the outputs of Flowdroid\n"
                    "- For each flowdroid log, a matrix counting all flows is obtained."
                    "- For a set of flowdroid logs, a matrix counting all flows for"
                    "  all apps is also obtained."
                    "- Outputs are generated in CSV files. \n\n",
        formatter_class=RawTextHelpFormatter)

    parser.add_argument('-s', '--source', help='Source directory for FlowDroid logs', required=True)

    parser.add_argument('-o', '--output_folder', help='Output directory for individual processed apks', required=False)

    parser.add_argument('-og', '--output_global_csv', help='Output directory for global matrix', required=False)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    process_flowdroid_outputs(flowdroid_analyses_folder=args.source_directory,
                              output_folder_individual_csv=args.output_folder,
                              output_csv_file=args.output_global_csv)


def find_index(lis, stri):
    for i, s in enumerate(lis):
        if stri in s:
            return i
    return -1


def load_categories(f):
    with open(f, 'r') as fp:
        content = fp.readlines()
    content = [x.strip() for x in content]
    cat_dic = {}
    cat_lis = set()

    for line in content:
        if line == "":
            continue
        if line.split(' % ')[1].strip() in cat_dic:
            cat_dic[line.split(' % ')[1].strip()].append(line.split(' % ')[0].strip())
        else:
            cat_dic[line.split(' % ')[1].strip()] = [line.split(' % ')[0].strip()]
        cat_lis.add(line.split(' % ')[0].strip())
    cat_lis.add('NOT_EXISTING')
    return cat_dic, list(cat_lis)


def fill_matrix_flows(mat, cat_list, cat_map, flows):
    for key, value_list in flows.iteritems():
        key_cat = get_category(key, cat_map)
        key_indexes = [cat_list.index(x) for x in key_cat]
        value_indexes = []
        for value in value_list:
            value_cat = get_category(value, cat_map)
            value_indexes.extend([cat_list.index(x) for x in value_cat])

        for key_i in key_indexes:
            for value_i in value_indexes:
                mat[key_i][value_i] += 1

    return mat


def combine_matrices(matrices, categories_list, output_combined_file_name):
    """
    Generates a csv file with all samples as rows and columns as the combination of all possible categories
    :param matrices: a dictionary with keys as apk names (hashes) and values as the 2d matrix
    :param categories_list: list of categories from prmDomains
    :param output_combined_file_name: name of the file to save the combined csv
    """
    # Permutations with repetition of all categories
    categories_combined_list = [[x + "-" + y for y in categories_list] for x in categories_list]

    # Flattening of categories combinations list
    categories_combined_list = [x for row in categories_combined_list for x in row]

    # Flattening of each app 2d matrix
    vectors = []
    for index, apk_key in enumerate(matrices.keys()):
        matrix = matrices[apk_key]
        vectors.append([apk_key] + [x for row in matrix for x in row])

    # Writing the whole matrix to a csv file
    with open(output_combined_file_name, 'wb') as myfile:
        wr = csv.writer(myfile)
        wr.writerow(["apk"] + categories_combined_list)
        for row in vectors:
            wr.writerow(row)


def get_category(k, c_map):
    if k in c_map:
        return c_map[k]  # return a list
    else:
        return ['NOT_EXISTING']  # when is not in our list, custom calls


def save_as_csv(path, dic, headers):
    with open(path, 'wb') as csvfile:
        writer = csv.writer(csvfile)
        tmp_lis = headers[:]
        tmp_lis.insert(0, 'Sources\Sinks')
        writer.writerow(tmp_lis)
        for ind in xrange(len(headers)):
            tmp_lis = dic[ind][:]
            tmp_lis.insert(0, headers[ind])
            writer.writerow(tmp_lis)


def process_flowdroid_outputs(flowdroid_analyses_folder, output_folder_individual_csv, output_csv_file, with_color=True):

    if not os.path.exists(output_folder_individual_csv):
        os.makedirs(output_folder_individual_csv)

    categories_map, categories_list = load_categories(PRM_DOMAINS)

    flowdroid_analysis_files = []
    for path, subdirs, files in os.walk(flowdroid_analyses_folder):
        for name in files:
            flowdroid_analysis_files.append(os.path.join(path, name))

    matrices = {}
    for flow_file in tqdm(flowdroid_analysis_files):

        # apk_id = flow_file.split("/")[-1]
        with open(flow_file, 'r') as fp:
            content = fp.readlines()

        ind = find_index(content, 'Found a flow to sink')
        flow_content = content[ind:-2]
        flow_content = [x.strip() for x in flow_content]

        dic = {}

        while len(flow_content) > 0:
            ind1 = find_index(flow_content, 'Found a flow to sink')
            tmp_key = flow_content[0]
            flow_content.pop(ind1)
            ind2 = find_index(flow_content, 'Found a flow to sink')
            if ind2 == -1:
                tmp_value = flow_content[ind1:]
                flow_content = []
            else:
                tmp_value = flow_content[ind1:ind2]
                flow_content = flow_content[ind2:]

            dic[tmp_key] = tmp_value

        dic_new = {}
        for key, value_list in dic.iteritems():
            if re.search('(<.*?>)', key).group(1) in dic_new:
                for value in value_list:
                    dic_new[re.search('(<.*?>)', key).group(1)].append(re.search('(<.*?>)', value).group(1))
            else:
                dic_new[re.search('(<.*?>)', key).group(1)] = []
                for value in value_list:
                    dic_new[re.search('(<.*?>)', key).group(1)].append(re.search('(<.*?>)', value).group(1))

        w, h = len(categories_list), len(categories_list)
        matrix = [[0 for _ in xrange(w)] for _ in xrange(h)]

        matrix = fill_matrix_flows(matrix, categories_list, categories_map, dic_new)

        output_individual_name = os.path.join(output_folder_individual_csv,
                                              os.path.basename(flow_file).replace(".json", "") + ".csv")
        save_as_csv(output_individual_name, matrix, categories_list)

        matrices[flow_file] = matrix

    combine_matrices(matrices, categories_list, output_csv_file)

    print_message('Success!!', with_color, 'green')
    print_message('Output folder: ' + str(output_folder_individual_csv), with_color, 'blue')


if __name__ == '__main__':
    main()

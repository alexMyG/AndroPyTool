import os

from flask import jsonify

import files_repository
import reports_repository
from androPyTool import execute_andro_py_tool_steps
from aux_functions import get_sha256


def upload_apk(uploaded_file, virus_total_api_key):
    sha256 = get_sha256(uploaded_file)

    if reports_repository.app_has_report(sha256):
        return jsonify({'resource_uri': 'reports/' + sha256}), 202
    else:
        source_folder, has_name_changed = files_repository.save_apk(sha256, uploaded_file)

        execute_andro_py(source_folder, virus_total_api_key)

        reports_repository.update_report(sha256)

        return jsonify({'resource_uri': 'files/' + sha256}), 202


def execute_andro_py(source_folder, virus_total_api_key):
    if virus_total_api_key is None:
        with open(os.path.join("rest_api", 'virus_total_api_key')) as f:
            virus_total_api_key = f.read()

    execute_andro_py_tool_steps(source_folder=source_folder,
                                step_filter_apks=True,
                                step_filter_bw_mw=False,
                                step_run_flowdroid=True,
                                step_run_droidbox=True,
                                save_single_analysis=True,
                                perform_nocleanup=False,
                                package_index='info/package_index.txt',
                                class_index='info/class_index.txt',
                                system_commands_index='info/system_commands.txt',
                                export_mongodb=None,
                                exportCSV=None,
                                with_color=True,
                                vt_threshold=1,
                                droidbox_time=10,
                                virus_total_api_key=virus_total_api_key
                                )

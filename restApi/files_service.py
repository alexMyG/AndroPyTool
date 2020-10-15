import os

from werkzeug.utils import secure_filename

import reports_repository
from androPyTool import execute_andro_py_tool_steps
from aux_functions import get_sha256


def upload_apk(uploaded_file, virus_total_api_key):
    filename = secure_filename(uploaded_file.filename)

    if reports_repository.app_has_report(filename):
        return "URI to report"
    else:
        sha256 = get_sha256(uploaded_file)
        directory = os.path.join("restApi", "files", sha256)

        if not os.path.exists(directory):
            os.makedirs(directory)

        uploaded_file.save(os.path.join(directory, filename))

        if virus_total_api_key is None:
            with open(os.path.join("restApi", 'virus_total_api_key')) as f:
                virus_total_api_key = f.read()

        execute_andro_py_tool_steps(source_folder=directory,
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
                                    droidbox_time=300,
                                    virus_total_api_key=virus_total_api_key
                                    )

        return "scan_apk()"

import json
import os

from aux_functions import throw_error


def get_all_reports():
    with open(os.path.join("/apks", "all_reports.json")) as f:
        return json.load(f)


def app_has_report(sha256):
    source_folder = os.path.join("/apks", sha256)

    return os.path.exists(source_folder)


def get_pre_static_analysis(sha256):
    analysis_json = read_analysis_json(sha256)

    remove_pre_static_vt(analysis_json["Pre_static_analysis"])

    return analysis_json["Pre_static_analysis"]


def get_dynamic_analysis(sha256):
    analysis_json = read_analysis_json(sha256)

    return analysis_json["Dynamic_analysis"]


def get_dynamic_analysis_droidbox(sha256):
    analysis_json = read_analysis_json(sha256)

    return analysis_json["Dynamic_analysis"]["Droidbox"]


def get_dynamic_analysis_strace(sha256):
    strace_folder = os.path.join("/apks", sha256, "Dynamic", "Strace")
    return os.path.join(strace_folder, os.listdir(strace_folder)[0])


def get_virusTotal_analysis(sha256):
    analysis_json = read_analysis_json(sha256)

    return analysis_json["VirusTotal"]["permalink"]


def get_static_analysis(sha256):
    analysis_json = read_analysis_json(sha256)

    return analysis_json["Static_analysis"]


def get_static_analysis_androPyTool(sha256):
    analysis_json = read_analysis_json(sha256)

    remove_fd(analysis_json["Static_analysis"])

    return analysis_json["Static_analysis"]


def get_static_analysis_flowDroid(sha256):
    analysis_json = read_analysis_json(sha256)

    return analysis_json["Static_analysis"]["FlowDroid"]


def get_complete_analysis(sha256):
    analysis_json = read_analysis_json(sha256)

    remove_pre_static_vt(analysis_json["Pre_static_analysis"])
    remove_vt(analysis_json["VirusTotal"])

    return analysis_json


def read_analysis_json(sha256):
    try:
        source_folder = os.path.join("/apks", sha256, "Features_files")
        analysis_file = [f for f in os.listdir(source_folder) if f.endswith("analysis.json")][0]
        with open(os.path.join(source_folder, analysis_file)) as f:
            return json.load(f)
    except:
        invalid_folder = os.path.join("/apks", sha256, "invalid_apks")
        if os.path.exists(invalid_folder) and len(os.listdir(invalid_folder)) > 0:
            throw_error("Apk is invalid", 200)
        else:
            throw_error("Report is corrupted", 500)


def remove_pre_static_vt(pre_static_analysis):
    vt_keys = ["VT_positives", "VT_engines", "avclass"]

    for key in vt_keys:
        pre_static_analysis.pop(key)


def remove_vt(analysis_vt):
    permalink = analysis_vt["permalink"]
    analysis_vt.clear()
    analysis_vt["permalink"] = permalink


def remove_fd(static_analysis):
    static_analysis.pop("FlowDroid")


def update_report(sha256):
    source_folder = os.path.join("/apks", sha256, "Features_files")
    analysis_file = [f for f in os.listdir(source_folder) if f.endswith("analysis.json")][0]
    with open(os.path.join(source_folder, analysis_file)) as f:
        json_analysis = json.load(f)
        if "Droidbox" in json_analysis["Dynamic_analysis"]:
            json_analysis["Dynamic_analysis"]["Droidbox"]["apkName"] = json_analysis["Pre_static_analysis"]["Filename"]
        if "Strace" in json_analysis["Dynamic_analysis"]:
            json_analysis["Dynamic_analysis"]["Strace"] = "reports/" + sha256 + "/dynamic/strace"

    with open(os.path.join(source_folder, analysis_file), 'w') as f:
        json.dump(json_analysis, f)

    with open(os.path.join("/apks", "all_reports.json")) as f:
        all_reports = json.load(f)

    remove_pre_static_vt(json_analysis["Pre_static_analysis"])
    all_reports["all_reports"].append(json_analysis["Pre_static_analysis"])

    with open(os.path.join("/apks", "all_reports.json"), 'w') as f:
        json.dump(all_reports, f)

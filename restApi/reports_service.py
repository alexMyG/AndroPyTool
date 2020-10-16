import reports_repository
from aux_functions import throw_error


def get_all_reports():
    return reports_repository.get_all_reports()


def get_pre_static_analysis(sha256):
    if reports_repository.app_has_report(sha256):
        return reports_repository.get_pre_static_analysis(sha256)
    else:
        throw_error("Report not found", 404)


def get_dynamic_analysis(sha256):
    if reports_repository.app_has_report(sha256):
        return reports_repository.get_dynamic_analysis(sha256)
    else:
        throw_error("Dynamic report not found", 404)


def get_dynamic_analysis_droidbox(sha256):
    if reports_repository.app_has_report(sha256):
        return reports_repository.get_dynamic_analysis_droidbox(sha256)
    else:
        throw_error("DroidBox report not found", 404)


def get_dynamic_analysis_strace(sha256):
    if reports_repository.app_has_report(sha256):
        return reports_repository.get_dynamic_analysis_strace(sha256)
    else:
        throw_error("Strace report not found", 404)


def get_virusTotal_analysis(sha256):
    if reports_repository.app_has_report(sha256):
        return reports_repository.get_virusTotal_analysis(sha256)
    else:
        throw_error("VirusTotal report not found", 404)


def get_static_analysis(sha256):
    if reports_repository.app_has_report(sha256):
        return reports_repository.get_static_analysis(sha256)
    else:
        throw_error("Static report not found", 404)


def get_static_analysis_androPyTool(sha256):
    if reports_repository.app_has_report(sha256):
        return reports_repository.get_static_analysis_androPyTool(sha256)
    else:
        throw_error("AndroPyTool report not found", 404)


def get_static_analysis_flowDroid(sha256):
    if reports_repository.app_has_report(sha256):
        return reports_repository.get_static_analysis_flowDroid(sha256)
    else:
        throw_error("FlowDroid report not found", 404)


def get_complete_analysis(sha256):
    if reports_repository.app_has_report(sha256):
        return reports_repository.get_complete_analysis(sha256)
    else:
        throw_error("Complete report not found", 404)

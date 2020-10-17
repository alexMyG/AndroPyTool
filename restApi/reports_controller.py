from flask import Blueprint, send_file
from markupsafe import escape

import reports_service

app_reports = Blueprint('app_reports', __name__)


@app_reports.route('/reports', methods=['GET'])
def get_all_reports():
    return reports_service.get_all_reports()


@app_reports.route('/reports/<sha256>', methods=['GET'])
def get_pre_static_analysis(sha256):
    return reports_service.get_pre_static_analysis(escape(sha256))


@app_reports.route('/reports/<sha256>/dynamic', methods=['GET'])
def get_dynamic_analysis(sha256):
    return reports_service.get_dynamic_analysis(escape(sha256))


@app_reports.route('/reports/<sha256>/dynamic/droidbox', methods=['GET'])
def get_dynamic_analysis_droidbox(sha256):
    return reports_service.get_dynamic_analysis_droidbox(escape(sha256))


@app_reports.route('/reports/<sha256>/dynamic/strace', methods=['GET'])
def get_dynamic_analysis_strace(sha256):
    return send_file(
        reports_service.get_dynamic_analysis_strace(escape(sha256)),
        mimetype="text/csv",
        attachment_filename="strace_" + sha256 + ".csv"
    )


@app_reports.route('/reports/<sha256>/virustotal', methods=['GET'])
def get_virusTotal_analysis(sha256):
    return reports_service.get_virusTotal_analysis(escape(sha256))


@app_reports.route('/reports/<sha256>/static', methods=['GET'])
def get_static_analysis(sha256):
    return reports_service.get_static_analysis(escape(sha256))


@app_reports.route('/reports/<sha256>/static/andropytool', methods=['GET'])
def get_static_analysis_androPyTool(sha256):
    return reports_service.get_static_analysis_androPyTool(escape(sha256))


@app_reports.route('/reports/<sha256>/static/flowdroid', methods=['GET'])
def get_static_analysis_flowDroid(sha256):
    return reports_service.get_static_analysis_flowDroid(escape(sha256))


@app_reports.route('/reports/<sha256>/complete', methods=['GET'])
def get_complete_analysis(sha256):
    return reports_service.get_complete_analysis(escape(sha256))

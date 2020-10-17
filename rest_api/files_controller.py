from flask import request, Blueprint

import files_service
from aux_functions import throw_error

app_files = Blueprint('app_files', __name__)


@app_files.route('/files', methods=['POST'])
def upload_file():
    check_file()
    virus_total_api_key = request.args.get('virus_total_api_key')
    return files_service.upload_apk(request.files['file'], virus_total_api_key)


def check_file():
    if 'file' not in request.files:
        throw_error("No file part", 400)
    if len(request.files.getlist('file')) > 1:
        throw_error("Only one file upload is allowed", 400)

    uploaded_file = request.files['file']

    if uploaded_file.filename == '':
        throw_error("No selected file", 400)
    if not is_allowed_extension(uploaded_file.filename):
        throw_error("Only .apk extension is allowed", 400)


def is_allowed_extension(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'apk'

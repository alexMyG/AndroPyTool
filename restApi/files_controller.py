from flask import request, abort, Blueprint

import files_service

app_files = Blueprint('app_files', __name__)


@app_files.route('/files', methods=['POST'])
def upload_file():
    check_file()
    virus_total_api_key = request.args.get('virus_total_api_key')
    return files_service.upload_apk(request.files['file'], virus_total_api_key)


def check_file():
    if 'file' not in request.files:
        abort(400, 'No file part')
    if len(request.files.getlist('file')) > 1:
        abort(400, 'Only one file upload is allowed')

    uploaded_file = request.files['file']

    if uploaded_file.filename == '':
        abort(400, 'No selected file')
    if not is_allowed_extension(uploaded_file.filename):
        abort(400, 'Only .apk extension is allowed')


def is_allowed_extension(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'apk'

import os

from werkzeug.utils import secure_filename


def save_apk(sha256, uploaded_file):
    filename = secure_filename(uploaded_file.filename)
    source_folder = os.path.join("/apks", sha256)

    if not os.path.exists(source_folder):
        os.makedirs(source_folder)

    uploaded_file.save(os.path.join(source_folder, filename))

    has_name_changed = (filename == uploaded_file.filename)

    return source_folder, has_name_changed
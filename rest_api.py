import os

from flask import Flask

from rest_api.files_controller import app_files
from rest_api.reports_controller import app_reports

main_app = Flask(__name__)
main_app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB
main_app.register_blueprint(app_reports)
main_app.register_blueprint(app_files)

# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    if not os.path.exists(os.path.join("/apks", "all_reports.json")):
        with open("/apks", "all_reports.json", 'w') as f:
            f.write('[]')

    main_app.run(port=5000, host='0.0.0.0', threaded=False)

import os
import sys

from flask import Flask
from flask_cors import CORS

from rest_api.files_controller import app_files
from rest_api.reports_controller import app_reports

main_app = Flask(__name__)
main_app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB
main_app.register_blueprint(app_reports)
main_app.register_blueprint(app_files)
CORS(main_app)

if not os.path.exists(os.path.join("rest_api", 'virus_total_api_key')):
    print "You have to add a default virusTotal API key on file 'rest_api/virus_total_api_key'"
    sys.exit(1)

if not os.path.exists(os.path.join("/apks", "all_reports.json")):
    with open(os.path.join("/apks", "all_reports.json"), 'w') as f:
        f.write('{"all_reports":[]}')

# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    main_app.run(port=5000, host='0.0.0.0', threaded=False)

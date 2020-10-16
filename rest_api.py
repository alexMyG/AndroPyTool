from flask import Flask

from restApi.reports_controller import app_reports
from restApi.files_controller import app_files

main_app = Flask(__name__)
main_app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB
main_app.register_blueprint(app_reports)
main_app.register_blueprint(app_files)

# If we're running in stand alone mode, run the application
if __name__ == '__main__':
    main_app.run(port=5000, debug=True, host='0.0.0.0')

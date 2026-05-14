from flask import Flask, request, send_file, send_from_directory, redirect, url_for, flash, render_template, jsonify
import os
import shutil
import sys
import tempfile
import uuid
import zipfile
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
APP_DIR = os.path.join(PROJECT_DIR, "app")
DEMO_DIR = os.path.join(APP_DIR, "demo")
DEMO_INPUT_FILENAME = "12id.xlsx"
DEMO_INPUT_PATH = os.path.join(DEMO_DIR, DEMO_INPUT_FILENAME)

for path in [PROJECT_DIR, APP_DIR]:
    if path not in sys.path:
        sys.path.insert(0, path)

app = Flask(
    __name__,
    template_folder=os.path.join(APP_DIR, "templates"),
    static_folder=os.path.join(APP_DIR, "static")
)

app.secret_key = os.getenv("FLASK_SECRET_KEY", "demo-only-secret-key")

IS_VERCEL = os.getenv("VERCEL") == "1"
PUBLIC_DEMO_MODE = os.getenv(
    "PUBLIC_DEMO_MODE",
    "false"
).lower() == "true"

app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024
app.config['UPLOAD_EXTENSIONS'] = ['.csv', '.xlsx', '.xls']  # limit to CSV and Excel files


def allowed_file(filename):
    return '.' in filename and \
           os.path.splitext(filename)[1].lower() in app.config['UPLOAD_EXTENSIONS']


def ensure_runtime_config():
    key = os.getenv("KEY")
    if not key:
        raise RuntimeError("Missing KEY environment variable. Set a 32-character hex key in Vercel.")
    if len(key) != 32:
        raise RuntimeError("Invalid KEY environment variable. It must be a 32-character hex key.")
    try:
        int(key, 16)
    except ValueError as exc:
        raise RuntimeError("Invalid KEY environment variable. It must contain only hexadecimal characters.") from exc


def get_processing_modules():
    ensure_runtime_config()
    from engine.encrypt_engine import encryption, decryption
    from excel.excel_handler import excel_to_csv, csv_to_excel
    return encryption, decryption, excel_to_csv, csv_to_excel


def make_work_dir():
    temp_root = tempfile.gettempdir() if IS_VERCEL else os.path.join(PROJECT_DIR, ".tmp")
    work_dir = os.path.join(temp_root, f"vaultcipher-{uuid.uuid4().hex}")
    os.makedirs(work_dir, exist_ok=False)
    return work_dir


def attach_cleanup(response, work_dir):
    response.call_on_close(lambda: shutil.rmtree(work_dir, ignore_errors=True))
    return response


def build_zip_response(input_path, filename, algorithm):
    encryption, _, excel_to_csv, csv_to_excel = get_processing_modules()

    work_dir = make_work_dir()
    upload_dir = os.path.join(work_dir, "uploads")
    output_dir = os.path.join(work_dir, "output")
    os.makedirs(upload_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    saved_input_path = os.path.join(upload_dir, secure_filename(filename))
    shutil.copyfile(input_path, saved_input_path)

    encrypted_csv_path = excel_to_csv(saved_input_path, upload_dir)
    public_csv_file, metadata_csv_file = encryption(encrypted_csv_path, output_dir, algorithm)
    public_xlsx_file = csv_to_excel(public_csv_file, output_dir)
    metadata_xlsx_file = csv_to_excel(metadata_csv_file, output_dir)

    zip_filename = f"result_{os.path.splitext(os.path.basename(filename))[0]}.zip"
    zip_path = os.path.join(output_dir, zip_filename)

    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.write(public_xlsx_file, arcname=os.path.basename(public_xlsx_file))
        zf.write(metadata_xlsx_file, arcname=os.path.basename(metadata_xlsx_file))

    return attach_cleanup(send_file(zip_path, as_attachment=True), work_dir)


def build_zip_upload_response(file_storage, filename, algorithm):
    encryption, _, excel_to_csv, csv_to_excel = get_processing_modules()

    work_dir = make_work_dir()
    upload_dir = os.path.join(work_dir, "uploads")
    output_dir = os.path.join(work_dir, "output")
    os.makedirs(upload_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    saved_input_path = os.path.join(upload_dir, secure_filename(filename))
    file_storage.save(saved_input_path)

    encrypted_csv_path = excel_to_csv(saved_input_path, upload_dir)
    public_csv_file, metadata_csv_file = encryption(encrypted_csv_path, output_dir, algorithm)
    public_xlsx_file = csv_to_excel(public_csv_file, output_dir)
    metadata_xlsx_file = csv_to_excel(metadata_csv_file, output_dir)

    zip_filename = f"result_{os.path.splitext(os.path.basename(filename))[0]}.zip"
    zip_path = os.path.join(output_dir, zip_filename)

    with zipfile.ZipFile(zip_path, 'w') as zf:
        zf.write(public_xlsx_file, arcname=os.path.basename(public_xlsx_file))
        zf.write(metadata_xlsx_file, arcname=os.path.basename(metadata_xlsx_file))

    return attach_cleanup(send_file(zip_path, as_attachment=True), work_dir)


def build_decrypt_response(input_path, filename):
    _, decryption, excel_to_csv, csv_to_excel = get_processing_modules()

    work_dir = make_work_dir()
    upload_dir = os.path.join(work_dir, "uploads")
    output_dir = os.path.join(work_dir, "output")
    os.makedirs(upload_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    saved_input_path = os.path.join(upload_dir, secure_filename(filename))
    shutil.copyfile(input_path, saved_input_path)

    decrypted_csv_path = excel_to_csv(saved_input_path, upload_dir)
    decrypted_file = decryption(decrypted_csv_path, output_dir)
    decrypted_xlsx_file = csv_to_excel(decrypted_file, output_dir)

    return attach_cleanup(send_file(decrypted_xlsx_file, as_attachment=True), work_dir)


def build_decrypt_upload_response(file_storage, filename):
    _, decryption, excel_to_csv, csv_to_excel = get_processing_modules()

    work_dir = make_work_dir()
    upload_dir = os.path.join(work_dir, "uploads")
    output_dir = os.path.join(work_dir, "output")
    os.makedirs(upload_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    saved_input_path = os.path.join(upload_dir, secure_filename(filename))
    file_storage.save(saved_input_path)

    decrypted_csv_path = excel_to_csv(saved_input_path, upload_dir)
    decrypted_file = decryption(decrypted_csv_path, output_dir)
    decrypted_xlsx_file = csv_to_excel(decrypted_file, output_dir)

    return attach_cleanup(send_file(decrypted_xlsx_file, as_attachment=True), work_dir)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", public_demo_mode=PUBLIC_DEMO_MODE)


@app.route("/style.css", methods=["GET"])
def style_css():
    return send_from_directory(os.path.join(APP_DIR, "static"), "style.css")


@app.route("/workspace", methods=["GET"])
def workspace():
    return render_template("workspace.html", public_demo_mode=PUBLIC_DEMO_MODE)


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({
        "ok": True,
        "public_demo_mode": PUBLIC_DEMO_MODE,
        "vercel": IS_VERCEL,
        "key_configured": bool(os.getenv("KEY")),
    })


@app.route("/demo/encrypt", methods=["POST"])
def demo_encrypt():
    try:
        algorithm = request.form.get("algorithm", "FF1")
        return build_zip_response(DEMO_INPUT_PATH, DEMO_INPUT_FILENAME, algorithm)
    except Exception as e:
        print(f"Demo Encrypt Error: {e}")
        flash(f"failed demo encryption: {str(e)}")
        return redirect(url_for("workspace"))


@app.route("/demo/decrypt", methods=["POST"])
def demo_decrypt():
    try:
        encryption, decryption, excel_to_csv, csv_to_excel = get_processing_modules()

        work_dir = make_work_dir()
        upload_dir = os.path.join(work_dir, "uploads")
        output_dir = os.path.join(work_dir, "output")
        os.makedirs(upload_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)

        saved_input_path = os.path.join(upload_dir, DEMO_INPUT_FILENAME)
        shutil.copyfile(DEMO_INPUT_PATH, saved_input_path)

        encrypted_csv_path = excel_to_csv(saved_input_path, upload_dir)
        _, metadata_csv_file = encryption(encrypted_csv_path, output_dir, "FF1")
        metadata_xlsx_file = csv_to_excel(metadata_csv_file, output_dir)

        decrypted_csv_path = excel_to_csv(metadata_xlsx_file, upload_dir)
        decrypted_file = decryption(decrypted_csv_path, output_dir)
        decrypted_xlsx_file = csv_to_excel(decrypted_file, output_dir)

        return attach_cleanup(send_file(decrypted_xlsx_file, as_attachment=True), work_dir)
    except Exception as e:
        print(f"Demo Decrypt Error: {e}")
        flash(f"failed demo decryption: {str(e)}")
        return redirect(url_for("workspace"))

@app.route("/encrypt", methods=["POST"])
def encrypt():
    if PUBLIC_DEMO_MODE and IS_VERCEL:
        flash("Public demo mode only processes bundled demo files. Visitor uploads are disabled.")
        return redirect(url_for("workspace"))

    if 'file' not in request.files:
        flash("No input file, please select a file")
        return redirect(url_for("workspace"))

    file = request.files['file']

    if file.filename == '':
        flash("Please upload a file")
        return redirect(url_for("workspace"))

    # avoid path traversal
    filename = secure_filename(file.filename)
    """
    # check file extension
    file_ext = os.path.splitext(filename)[1]
    if file_ext not in app.config['UPLOAD_EXTENSIONS']:
        return "Unsupported file format", 400
    """
    # get choosen algorithm
    algorithm = request.form.get("algorithm")

    if file and allowed_file(file.filename):
        try:
            return build_zip_upload_response(file, filename, algorithm)
    
        except Exception as e:
            print(f"Encrypt Error: {e}")
            flash(f"failed encryption: {str(e)}")
            return redirect(url_for("workspace"))
    else:
        return "Unsupported file format", 400

@app.route("/decrypt", methods=["POST"])
def decrypt():
    if PUBLIC_DEMO_MODE and IS_VERCEL:
        flash("Public demo mode only processes bundled demo files. Visitor uploads are disabled.")
        return redirect(url_for("workspace"))

    if 'file' not in request.files:
        flash("No input file, please select a file")
        return redirect(url_for("workspace"))

    file = request.files['file']

    if file.filename == '':
        flash("Please upload a file")
        return redirect(url_for("workspace"))

    # avoid path traversal
    filename = secure_filename(file.filename)
    
    # check file extension
    file_ext = os.path.splitext(filename)[1]
    if file_ext not in app.config['UPLOAD_EXTENSIONS']:
        return "Unsupported file format", 400

    if file and allowed_file(file.filename):
        try:
            return build_decrypt_upload_response(file, filename)
        
        except Exception as e:
            print(f"Encrypt Error: {e}")
            flash(f"failed decryption: {str(e)}")
            return redirect(url_for("workspace"))
    else:
        return "Unsupported file format", 400
    

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

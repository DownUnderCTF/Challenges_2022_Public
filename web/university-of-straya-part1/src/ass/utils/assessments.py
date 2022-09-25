import base64
import tarfile
import zipfile
from pathlib import Path
import os
import magic
import subprocess

UPLOAD_FOLDER = os.path.join("/", "tmp", "students")

FILE_TYPE = 'file'
ARCHIVE_TYPE = 'zip'
JAVA_TYPE = 'java-underdevelopment'

EXTRACTED_FOLDER = 'extracted'

ASSESSMENT_TYPES = [
    FILE_TYPE,
    ARCHIVE_TYPE,
    JAVA_TYPE
]

ZIP_MIME = "application/zip"
TAR_MIME = "application/x-tar"
GZIP_MIME = "application/gzip"

ALLOWED_MIMES = [
    ZIP_MIME,
    TAR_MIME,
    GZIP_MIME
]

ALLOWED_ARCHIVE_EXTENSIONS = [
    "zip",
    "tar",
    "tar.gz"
]

def get_file(path: str) -> str:
    with open(path, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).encode()

def extract_tar(path: str) -> str:
    extract_folder = os.path.join(Path(path).parent, EXTRACTED_FOLDER)
    with tarfile.open(path) as tar:
        tar.extractall(path=extract_folder)
    os.remove(path)
    return extract_folder

def extract_zip(path: str) -> str:
    extract_folder = os.path.join(Path(path).parent, EXTRACTED_FOLDER)
    with zipfile.ZipFile(path, 'r') as zip_ref:
        zip_ref.extractall(extract_folder)
    os.remove(path)
    return extract_folder

def extract_file(path: str, file_type: str) -> str:
    if file_type == ZIP_MIME:
        return extract_zip(path)
    elif file_type in [TAR_MIME, GZIP_MIME]:
        return extract_tar(path)
    raise Exception("Mate wtf is this file type? I cannot extract this!")

def get_file_type(data: bytes) -> str:
    return magic.from_buffer(data, mime=True)

def save_to_random_file(data: bytes) -> tuple:
    folder = os.path.join(UPLOAD_FOLDER, os.urandom(8).hex())
    os.makedirs(folder, exist_ok=True)
    filename = os.urandom(8).hex()
    saved_path = os.path.join(folder, filename)
    with open(saved_path, 'wb') as f:
        f.write(data)
    return folder, filename

def list_files(folder: str, parent_folder='', allowed_ext=None) -> list:
    file_paths = []
    full_parent_folder = os.path.join(folder, parent_folder)
    for name in os.listdir(full_parent_folder):
        full_path = os.path.join(full_parent_folder, name)
        if os.path.isfile(full_path):
            if not allowed_ext is None: 
                if os.path.splitext(full_path)[1] == allowed_ext:
                    file_paths.append(os.path.join(parent_folder, name))
            else:
                file_paths.append(os.path.join(parent_folder, name))
        else:
            file_paths.extend(
                list_files(
                    folder, 
                    parent_folder=os.path.join(parent_folder, name), 
                    allowed_ext=allowed_ext
                )
            )
    return sorted(file_paths, reverse=True)

def check_java_is_valid(folder)->bool:
    class_files = list_files(folder, allowed_ext=".java")

    temp_output = os.path.join("/", "tmp", "java", os.urandom(8).hex())
    os.makedirs(temp_output, exist_ok=True)
    old_cwd = os.getcwd()
    os.chdir(folder)

    # Using subprocess.run prevents any command injection students could exploit
    try:
        returned_code = subprocess.run(["/usr/bin/javac", "-d", temp_output]+class_files)
    except:
        return False
    finally:
        os.chdir(old_cwd)
    
    return returned_code == 0
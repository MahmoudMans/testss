import os
import stat
import rarfile
import zipfile
import py7zr
import shutil
import logging
import time
import gc
import atexit
from exeextractor import analyze_executable

logging.basicConfig(level=logging.INFO)
rarfile.UNRAR_TOOL = r"C:\Program Files\UnRAR.exe"

def onerror(func, path, exc_info):
    try:
        os.chmod(path, stat.S_IWUSR)
        func(path)
    except Exception as e:
        logging.error(f"Error executing function {func.__name__} on {path}: {e}")

def retry_deletion(path, is_dir=False, max_retries=10):
    for attempt in range(max_retries):
        try:
            if is_dir:
                os.rmdir(path)
            else:
                os.chmod(path, stat.S_IWUSR)
                os.remove(path)
            break
        except Exception as e:
            logging.error(f"Retry {attempt + 1} failed to delete {path}: {e}")
            time.sleep(5)
            if attempt == max_retries - 1:
                logging.error(f"Unable to delete {path} after {max_retries} attempts.")

def empty_directory(directory):
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            file_path = os.path.join(root, name)
            retry_deletion(file_path)
        for name in dirs:
            dir_path = os.path.join(root, name)
            retry_deletion(dir_path, is_dir=True)

def safe_remove_directory(directory, attempts=10, wait=5):
    gc.collect()
    empty_directory(directory)
    for attempt in range(attempts):
        try:
            if os.path.exists(directory):
                shutil.rmtree(directory, onerror=onerror)
            break
        except Exception as e:
            logging.error(f"Attempt {attempt + 1} failed to remove directory {directory}: {e}")
            time.sleep(wait * (attempt + 1))

def list_and_analyze_executables_from_zip(zip_path, password="infected"):
    temp_dir = 'temp'
    os.makedirs(temp_dir, exist_ok=True)
    atexit.register(lambda: safe_remove_directory(temp_dir))
    try:
        with zipfile.ZipFile(zip_path, 'r') as archive:
            if password:
                archive.extractall(path=temp_dir, pwd=password.encode())
            else:
                archive.extractall(path=temp_dir)
        results = {}
        for root, _, files in os.walk(temp_dir):
            for file in files:
                if file.lower().endswith('.exe') or '.exe.' in file.lower():
                    executable_path = os.path.join(root, file)
                    results[file] = analyze_executable(executable_path)
        return results
    finally:
        time.sleep(5)

def convert_to_zip(input_path, zip_path, password="infected"):
    temp_dir = 'temp_extract'
    os.makedirs(temp_dir, exist_ok=True)
    try:
        if any(ext in input_path.lower() for ext in ['.rar', '.7z', '.zip']):
            # Extract based on file type, assuming the core archive type is identifiable before additional terminology
            if '.rar' in input_path.lower():
                with rarfile.RarFile(input_path) as rar:
                    rar.extractall(path=temp_dir, pwd=password)
            elif '.7z' in input_path.lower():
                with py7zr.SevenZipFile(input_path, mode='r', password=password) as sevenz:
                    sevenz.extractall(path=temp_dir)
            elif '.zip' in input_path.lower():
                with zipfile.ZipFile(input_path, 'r') as zfile:
                    zfile.extractall(path=temp_dir, pwd=password.encode())
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        in_zip_path = os.path.relpath(file_path, temp_dir)
                        zipf.write(file_path, arcname=in_zip_path)
    finally:
        safe_remove_directory(temp_dir)

def main():
    # Search for files that might contain extensions after the core archive format
    archive_files = [f for f in os.listdir('.') if any(f.lower().find(ext) != -1 for ext in ['.rar', '.7z', '.zip'])]

    for input_path in archive_files:
        zip_path = input_path + '_converted.zip'
        convert_to_zip(input_path, zip_path)
        zip_exe_results = list_and_analyze_executables_from_zip(zip_path)
        print(f"Executable Analysis Results from {zip_path}:", zip_exe_results)

if __name__ == "__main__":
    main()

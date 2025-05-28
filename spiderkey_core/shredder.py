import os
import shutil

class Shredder:
    def __init__(self, passes: int = 3):
        self.passes = passes  # Number of overwrite passes

    def shred_file(self, filepath: str):
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File '{filepath}' does not exist.")
        if not os.path.isfile(filepath):
            raise IsADirectoryError(f"Path '{filepath}' is not a file.")

        length = os.path.getsize(filepath)
        try:
            with open(filepath, "ba+", buffering=0) as f:
                for _ in range(self.passes):
                    f.seek(0)
                    f.write(os.urandom(length))
            os.remove(filepath)
        except Exception as e:
            raise RuntimeError(f"Failed to shred file '{filepath}': {e}")

    def shred_directory(self, dirpath: str):
        if not os.path.exists(dirpath):
            raise FileNotFoundError(f"Directory '{dirpath}' does not exist.")
        if not os.path.isdir(dirpath):
            raise NotADirectoryError(f"Path '{dirpath}' is not a directory.")

        for root, _, files in os.walk(dirpath, topdown=False):
            for file in files:
                self.shred_file(os.path.join(root, file))
            for folder in os.listdir(root):
                full_path = os.path.join(root, folder)
                if os.path.isdir(full_path):
                    shutil.rmtree(full_path, ignore_errors=True)
        shutil.rmtree(dirpath, ignore_errors=True)

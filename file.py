# File-IntegrityMonitor
import os
import time
import sys
import hashlib

"""
Advanced File Integrity Checker using SHA-256

This script scans all files in a specified directory and calculates their SHA-256 hashes.
It then compares each hash to a list of known (potentially malicious or sensitive) hashes
provided in an external file. It provides memory usage tracking and alerts the user
whenever a match is found.

This is useful for detecting known malicious files, verifying integrity, or scanning
against virus signature hashes (e.g., from VirusShare).

Usage:
------
    python integrity_checker.py <directory_to_scan> <known_hashes_file>

Example:
    python integrity_checker.py /home/user/documents/ /path/to/sha256_hash_list.txt

Dependencies:
-------------
    None (pure Python standard library)

Tested with Python 3.9+
"""

import psutil  # To track memory usage

# Initialize current process for memory tracking
process = psutil.Process(os.getpid())

# Threshold for memory usage warning in MB
MEMORY_THRESHOLD_MB = 300

def sha256_hash(file_path):
    """
    Calculate the SHA-256 hash of the given file.
    
    Args:
        file_path (str): Path to the file

    Returns:
        str or None: The SHA-256 hexadecimal digest of the file, or None if error
    """
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[Error] Could not process '{file_path}': {e}", flush=True)
        return None

def get_memory_usage_mb():
    """
    Get memory usage of the current process in megabytes.

    Returns:
        float: memory usage in MB
    """
    return process.memory_info().rss / (1024 * 1024)

def scan_directory_for_hashes(target_directory, hashlist_path):
    """
    Recursively scan the directory and compare file hashes to known hash list.

    Args:
        target_directory (str): The root directory to scan
        hashlist_path (str): Path to the file containing known SHA-256 hashes
    """
    known_hashes = set()
    match_found = False
    files_scanned = 0

    # Load known hashes
    try:
        with open(hashlist_path, "r") as f:
            for line in f:
                cleaned = line.strip().lower()
                if cleaned:
                    known_hashes.add(cleaned)
    except Exception as e:
        print(f"[Error] Failed to read hash list: {e}")
        return

    # Display initial memory usage
    print(f"[INFO] Initial memory usage: {get_memory_usage_mb():.2f} MB")
    start_time = time.time()

    # Count total files
    total_files = sum(len(files) for _, _, files in os.walk(target_directory))
    print(f"[INFO] Total files to scan: {total_files}")

    # Begin directory traversal
    for root, _, files in os.walk(target_directory):
        for name in files:
            current_memory = get_memory_usage_mb()
            if current_memory > MEMORY_THRESHOLD_MB:
                print(f"[WARNING] High memory usage: {current_memory:.2f} MB")

            file_path = os.path.join(root, name)
            hash_value = sha256_hash(file_path)

            if hash_value and hash_value.lower() in known_hashes:
                print(f"\033[91m[ALERT] Match found: {file_path}\033[0m", flush=True)
                match_found = True

            files_scanned += 1
            if files_scanned % 25 == 0:
                print(f"[INFO] Scanned {files_scanned} files...", flush=True)

    # Wrap-up
    elapsed = time.time() - start_time
    print("\n[INFO] Scan complete.")
    print(f"[INFO] Total files scanned: {files_scanned}")
    print(f"[INFO] Known hashes loaded: {len(known_hashes)}")
    print(f"[INFO] Time taken: {elapsed:.2f} seconds")
    if not match_found:
        print("[INFO] No matching hashes were found.")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python integrity_checker.py <directory_to_scan> <known_hashes_file>")
        sys.exit(1)

    directory = sys.argv[1]
    hash_file = sys.argv[2]

    scan_directory_for_hashes(directory, hash_file)

# Example hash list source:
# https://virusshare.com/hashes
# Example usage:
#   python integrity_checker.py ./documents ./malware_hashes.txt

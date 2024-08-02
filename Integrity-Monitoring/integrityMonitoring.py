import os
import hashlib
import argparse
import logging
import configparser

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load configuration from file
config = configparser.ConfigParser()
config.read('integrity_checker.cfg')

# Load the trusted database of hashes
try:
    trusted_db = config.get('integrity_checker', 'trusted_db')
except configparser.NoSectionError:
    logger.error("Configuration file not found or has incorrect format")
    exit(1)
except configparser.NoOptionError:
    logger.error("Trusted database file not specified in configuration")
    exit(1)

# Load the algorithm to use for hashing
try:
    algorithm = config.get('integrity_checker', 'algorithm')
except configparser.NoSectionError:
    logger.error("Configuration file not found or has incorrect format")
    exit(1)
except configparser.NoOptionError:
    logger.error("Hashing algorithm not specified in configuration")
    exit(1)

def calculate_checksum(file_path, algorithm):
    """
    Calculate the checksum of a file using the specified algorithm
    """
    if algorithm == 'sha256':
        hash_func = hashlib.sha256()
    elif algorithm == 'sha512':
        hash_func = hashlib.sha512()
    elif algorithm == 'md5':
        hash_func = hashlib.md5()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            hash_func.update(chunk)

    return hash_func.hexdigest()

def scan_directory(directory, algorithm):
    """
    Scan a directory and calculate the checksums of all files
    """
    checksums = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            checksum = calculate_checksum(file_path, algorithm)
            checksums[file_path] = checksum
    return checksums

def load_trusted_hashes(trusted_db):
    """
    Load the trusted hashes from the database
    """
    trusted_hashes = {}
    try:
        with open(trusted_db, 'r') as f:
            for line in f:
                file_path, checksum = line.strip().split(',')
                trusted_hashes[file_path] = checksum
    except FileNotFoundError:
        logger.error(f"Trusted database file not found: {trusted_db}")
        return {}
    except Exception as e:
        logger.error(f"Error loading trusted database: {e}")
        return {}
    return trusted_hashes

def check_integrity(checksums, trusted_hashes):
    """
    Check the integrity of the system files by comparing the calculated checksums with the trusted hashes
    """
    discrepancies = []
    for file_path, checksum in checksums.items():
        if file_path in trusted_hashes:
            if checksum != trusted_hashes[file_path]:
                discrepancies.append((file_path, checksum, trusted_hashes[file_path]))
        else:
            logger.warning(f"File {file_path} not found in trusted database")
    return discrepancies

def main():
    parser = argparse.ArgumentParser(description='Integrity Checker')
    parser.add_argument('-d', '--directory', help='Directory to scan')
    parser.add_argument('-a', '--algorithm', help='Algorithm to use (sha256, sha512, md5)', default=algorithm)
    parser.add_argument('-t', '--trusted-db', help='Trusted database file', default=trusted_db)
    args = parser.parse_args()

    # Load the trusted hashes
    trusted_hashes = load_trusted_hashes(args.trusted_db)

    # Scan the directory and calculate the checksums
    checksums = scan_directory(args.directory, args.algorithm)

    # Check the integrity of the system files
    discrepancies = check_integrity(checksums, trusted_hashes)

    # Print the results
    if discrepancies:
        logger.error("Discrepancies found:")
        for file_path, new_checksum, old_checksum in discrepancies:
            logger.error(f"File {file_path} has changed: old checksum {old_checksum}, new checksum {new_checksum}")
    else:
        logger.info("System files are intact")

if __name__ == '__main__':
    main()
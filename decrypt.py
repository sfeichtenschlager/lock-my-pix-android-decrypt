import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter
import argparse
import os
from pathlib import Path
import logging
import binascii

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s] %(asctime)s %(message)s',
    datefmt='%d-%m-%Y %H:%M:%S',
    handlers=[
        logging.FileHandler("LockMyPix_decryption_log.log"),
        logging.StreamHandler()
    ]
)

extension_map = {
    ".vp3": ".mp4",
    ".vo1": ".webm",
    ".v27": ".mpg",
    ".vb9": ".avi",
    ".v77": ".mov",
    ".v78": ".wmv",
    ".v82": ".dv",
    ".vz9": ".divx",
    ".vi3": ".ogv",
    ".v1u": ".h261",
    ".v6m": ".h264",
    ".6zu": ".jpg",
    ".tr7": ".gif",
    ".p5o": ".png",
    ".8ur": ".bmp",
    ".33t": ".tiff",
    ".20i": ".webp",
    ".v93": ".heic",
    ".v91": ".flv",
    ".v80": ".3gpp",
    ".vo4": ".ts",
    ".v99": ".mkv",
    ".vr2": ".mpeg",
    ".vv3": ".dpg",
    ".v81": ".rmvb",
    ".vz8": ".vob",
    ".wi2": ".asf",
    ".vi4": ".h263",
    ".v2u": ".f4v",
    ".v76": ".m4v",
    ".v75": ".ram",
    ".v74": ".rm",
    ".v3u": ".mts",
    ".v92": ".dng",
    ".r89": ".ps",
    ".v79": ".3gp",
}

def write_to_output(output_dir, relative_path, filename, dec_data):
    output_path = os.path.join(output_dir, relative_path)
    if not Path(output_path).exists():
        os.makedirs(output_path, exist_ok=True)

    base, ext = os.path.splitext(filename)
    if extension_map.get(ext):
        filename += extension_map.get(ext)
    else:
        filename += ".unknown"
        logging.warning(f"File {filename} has an unknown extension")

    file_path = os.path.join(output_path, filename)
    with open(file_path, "wb") as f:
        f.write(dec_data)
        logging.info(f"Decrypted file written to: {file_path}")

def decrypt_image(password, input_dir, output_dir):
    logging.info("Decryption started")
    logging.info(f"Password: {password}")
    logging.info(f"Input directory: {input_dir}")
    logging.info(f"Output directory: {output_dir}")

    key = hashlib.sha1(password.encode()).digest()[:16]
    iv = key
    logging.info(f"AES key: {key}")
    logging.info(f"AES IV: {iv}")

    if not Path(input_dir).exists():
        logging.warning(f"Input directory not found: {input_dir}")
        raise SystemExit(1)

    for root, _, files in os.walk(input_dir):
        relative_path = os.path.relpath(root, input_dir)
        for file in files:
            encrypted_path = os.path.join(root, file)

            # Skip directories
            if not os.path.isfile(encrypted_path):
                logging.warning(f"Skipping non-file: {encrypted_path}")
                continue

            # Create a new cipher object for each file
            counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
            cipher = AES.new(key, AES.MODE_CTR, counter=counter)

            logging.info(f"Processing file: {encrypted_path}")
            with open(encrypted_path, "rb") as enc_data:
                dec_data = cipher.decrypt(enc_data.read())
                write_to_output(output_dir, relative_path, file, dec_data)

def main():
    parser = argparse.ArgumentParser("LockMyPix Decrypt")
    parser.add_argument("password",
                        help="Enter the password for the application")
    parser.add_argument("input",
                        help="The directory of the exported encrypted files")
    parser.add_argument("output",
                        help="The directory for the decrypted files")

    args = parser.parse_args()
    decrypt_image(args.password, args.input, args.output)
    logging.info("Decryption Completed")

if __name__ == "__main__":
    main()

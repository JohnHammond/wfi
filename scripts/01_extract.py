#!/usr/bin/env python3

"""
This Python script looks through the Winbindex repository
and retrieves the GZIP compressed JSON file for every known
file for native Windows binaries (based off the binary filename)

It GUNZIP extracts this JSON file so that a later script
can run through the JSON data and determine the link necessary
to download the file from the Microsoft Symbol Server.

The output files from this script should only be stored
temporarily -- since they are used just to stage the information
needed to download all the binaries, the results of this script
do not need to be saved. 
"""


import json
import gzip
import glob
import os
import shutil

"""
This makes a total of

  1347 - *.exe.json.gz
  8043 - *.dll.json.gz
  712 - *.sys.json.gz

... 10102 extracted JSON files
"""

downloadable_file_extensions = ["exe", "dll", "sys"]

# Collect all the GZ files
gz_files_list = []
for ext in downloadable_file_extensions:
    file_pattern = f"../data/by_filename_compressed/*.{ext}.json.gz"
    gz_files_list += glob.glob(file_pattern)


for gz_file in gz_files_list:
    basename = os.path.basename(gz_file)
    extracted_name = basename.removesuffix(".gz")
    extracted_path = os.path.join("json_files", extracted_name)

    # Extract the GZ to the JSON file
    with gzip.open(gz_file, "rb") as f_in:
        with open(extracted_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

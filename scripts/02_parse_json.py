#!/usr/bin/env python3

"""
This Python script carves through the previously extracted
JSON data given by the Winbindex repository. Inside each JSON
file is a key field that represents a known SHA256 hash for
a rendition of that binary (whether it differed in an update or release)

Looking through each key, the script carves out the virtual size and
timestamp -- the two ingredients for being able to determine the
Microsoft Symbol Server. This script saved the Microsoft Symbol Server
URLs to an output file, `download_urls.json`
"""
import json
import os
import sys

my_json = {}


def get_symbol_server_url(filename: str, timestamp: int, virtualsize: int):

    return "https://msdl.microsoft.com/download/symbols/%s/%s/%s" % (
        filename,
        format(timestamp, "x").upper().rjust(8, "0") + format(virtualsize, "x"),
        filename,
    )


for root, dirs, files in os.walk("json_files"):
    for filename in files:
        fullpath = os.path.join(root, filename)
        j = json.load(open(fullpath))

        binary_filename = filename.removesuffix(".json")

        # Track this binary filename
        my_json[binary_filename] = {}

        for key in j:
            """
            key: the SHA256 hash of this binary
            """

            # Some hashes might not have data for us to grab the symbol URL
            # so we will set this as None to start
            my_json[binary_filename][key] = None

            try:
                fileinfo = j[key]["fileInfo"]
            except KeyError:
                sys.stderr.write(f"failed to find fileInfo for {binary_filename}\n")
                continue

            try:
                virtualsize = fileinfo["virtualSize"]
            except KeyError:
                sys.stderr.write(f"failed to find virtualsize for {binary_filename}\n")
                continue

            try:
                timestamp = fileinfo["timestamp"]
            except KeyError:
                sys.stderr.write(f"failed to find timestamp for {binary_filename}\n")
                continue

            symbol_url = get_symbol_server_url(binary_filename, timestamp, virtualsize)

            # If we were able to extract a symbol URL, save it for that hash
            my_json[binary_filename][key] = symbol_url

with open("download_urls.json", "w") as filp:
    json.dump(my_json, filp)

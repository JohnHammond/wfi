#!/usr/bin/env python3

"""
This Python script begins the process to update the Windows File Integrity process.
It checks against the previously downloaded data (files present in the '../data' dir),
retrieves the latest data, loops through it to find new hashes, and downloads
them from the Microsoft Symbol Server. It puts scripts 01-03 all together.
"""

import sys
import json
import gzip
import glob
import os
import shutil
import subprocess

import requests
import time
import urllib3

import asyncio
import httpx
import aiofiles
import aiofiles.os

import aiofiles.ospath

STAGING_BINARIES_DIR = "staging_binaries"
WINBINDEX_JSON_DIR = "winbindex_json"


sys.stderr.write("[+] collecting previously retrieved compressed json data...")

filenames = glob.glob("../data/*.json.xz")
previous_hashes = [ os.path.basename(fname).split(".")[0] for fname in filenames ]
sys.stderr.write(f"done!\n[+] found {len(previous_hashes)} previous files.\n")

sys.stderr.write("[+] creating staging json dir to get json data from winbindex repo... ")
try:
    os.mkdir(WINBINDEX_JSON_DIR)
    sys.stderr.write("done!\n")
except FileExistsError:
    pass
    sys.stderr.write("folder exists, good to go!\n")


sys.stderr.write("[+] creating staging binary dir to pull microsoft binaries... ")
try:
    os.mkdir(STAGING_BINARIES_DIR)
    sys.stderr.write("done!\n")
except FileExistsError:
    pass
    sys.stderr.write("folder exists, good to go!\n")

downloadable_file_extensions = ["exe", "dll", "sys"]

sys.stderr.write(f"[+] going to retrieve file data for only these extensions: {downloadable_file_extensions}\n")

sys.stderr.write("[+] pulling to receive latest updates from winbindex submodule... \n")
pull = subprocess.Popen("git pull", cwd="../winbindex")
pull.wait()


sys.stderr.write("[+] collecting new file data from winbindex... ")
# Collect all the GZ files
gz_files_list = []
for ext in downloadable_file_extensions:
    file_pattern = f"../winbindex/data/by_filename_compressed/*.{ext}.json.gz"
    gz_files_list += glob.glob(file_pattern)
sys.stderr.write(f"done! \n[+] found {len(gz_files_list)} files matching selected extensions.\n")

sys.stderr.write("[+] extracting new json data from latest winbindex into staging (this takes a minute or so)...")
sys.stderr.flush()
for gz_file in gz_files_list:
    basename = os.path.basename(gz_file)
    extracted_name = basename.removesuffix(".gz")
    extracted_path = os.path.join(WINBINDEX_JSON_DIR, extracted_name)

    # Extract the GZ to the JSON file
    with gzip.open(os.path.join(gz_file), "rb") as f_in:
        with open(extracted_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)


def get_symbol_server_url(filename: str, timestamp: int, virtualsize: int):

    return "https://msdl.microsoft.com/download/symbols/%s/%s/%s" % (
        filename,
        format(timestamp, "x").upper().rjust(8, "0") + format(virtualsize, "x"),
        filename,
    )


my_json = {}
new_counter = 0
sys.stderr.write(f"done!\n[+] looking through winbindex json for new hashes (this takes a few minutes)... ")
sys.stderr.flush()
for root, dirs, files in os.walk(WINBINDEX_JSON_DIR):
    for filename in files:
        fullpath = os.path.join(root, filename)
        j = json.load(open(fullpath, "rb"))

        binary_filename = filename.removesuffix(".json")

        # Track this binary filename
        my_json[binary_filename] = {}

        for key in j:
            # key: the SHA256 hash of this binary
            
            if key in previous_hashes:
                # ignore previously downloaded hashes
                # sys.stderr.write(f"[.] skipping hash {key} for {binary_filename}...\n")
                continue 

            # Some hashes might not have data for us to grab the symbol URL
            # so we will set this as None to start
            my_json[binary_filename][key] = None

            try:
                fileinfo = j[key]["fileInfo"]
            except KeyError:
                # sys.stderr.write(f"[!] failed to find fileInfo for {binary_filename} {key}\n")
                continue

            try:
                virtualsize = fileinfo["virtualSize"]
            except KeyError:
                # sys.stderr.write(f"[!] failed to find virtualsize for {binary_filename}\n")
                continue

            try:
                timestamp = fileinfo["timestamp"]
            except KeyError:
                # sys.stderr.write(f"[!] failed to find timestamp for {binary_filename}\n")
                continue

            symbol_url = get_symbol_server_url(binary_filename, timestamp, virtualsize)

            # If we were able to extract a symbol URL, save it for that hash
            my_json[binary_filename][key] = symbol_url
            # sys.stderr.write(f"[+] added hash {key} for {binary_filename}!\n")
            new_counter += 1


DOWNLOAD_URLS_FILENAME = "download_urls.json"
sys.stderr.write(f"done!\n[+] we see {new_counter} new hashes to retrieve\n")
with open(os.path.join(DOWNLOAD_URLS_FILENAME), "w") as filp:
    json.dump(my_json, filp)


sys.stderr.write(f"[+] downloading {new_counter} binaries from Microsoft Symbol Server (this may a few hours)...\n")

num_downloaded = 0
num_missed = 0
async def process_url(client, queue):

    while True:
        count, url, outputname = await queue.get()

        try:
            async with client.stream("GET", url, follow_redirects=True) as r:
                async with aiofiles.open(outputname, "wb") as f:
                    filesize = 0
                    async for block in r.aiter_bytes():
                        await f.write(block)
                        filesize += len(block)
                    if not filesize:
                        await queue.put((count + 1, url, outputname))

        except httpx.RequestError as exc:
            # Requeue for later
            if count > 5:
                print(f"[!] error: {url}: {type(exc)} {exc}")
            else:
                await queue.put((count + 1, url, outputname))
                # Wait for a second to prevent obliterating the server
                await asyncio.sleep(5)

async def download():
    global num_downloaded

    # Number of concurrent tasks
    NTASKS = 300
    limits = httpx.Limits(max_connections=NTASKS + 10)

    j = json.load(open(os.path.join(DOWNLOAD_URLS_FILENAME)))

    async with httpx.AsyncClient(limits=limits, timeout=20) as client:
        # Build background tasks
        queue = asyncio.Queue()
        tasks = [asyncio.create_task(process_url(client, queue)) for _ in range(NTASKS)]

        for binary_filename in j:
            for sha256hash in j[binary_filename]:

                if j[binary_filename][sha256hash]:
                    url = j[binary_filename][sha256hash]

                    save_filename = f"{sha256hash}_{binary_filename}"
                    save_path = os.path.join(STAGING_BINARIES_DIR, save_filename)

                    downloaded = False
                    if await aiofiles.ospath.exists(save_path):
                        if await aiofiles.ospath.getsize(save_path) > 0:
                            # print(f"NOT downloading {save_filename}")
                            downloaded = True
                            num_downloaded += 1
                        else:
                            print(
                                f"{num_downloaded} downloaded, {num_missed} missed: EMPTY {save_filename}, re-downloading..."
                            )
                            downloaded = False
                            num_missed += 1

                    if not downloaded:
                        await queue.put((0, url, save_path))

        await queue.join()

        for task in tasks:
            task.cancel()
            try:
                await task
            except:
                pass

sys.stderr.write("[+] creating staging binaries dir... ")
try:
    os.mkdir(STAGING_BINARIES_DIR)
    sys.stderr.write("done!\n")
except FileExistsError:
    pass
    sys.stderr.write("folder exists, good to go!\n")

# This will never seem to quit, and may not reach the end here.
# It might need to be manually stopped after you confirmed all (as much as possible) are downloaded
asyncio.run(download())

sys.stderr.write("[+] all done downloading binaries!\n")
sys.stderr.write("[+] now you need to run the golang enrichment:\n")
sys.stderr.write("     cd ../enrichment\n")
sys.stderr.write("     go run wfi.go -d ../scripts/staging_binaries -w ../scripts/winbindex_json -o ../data\n")
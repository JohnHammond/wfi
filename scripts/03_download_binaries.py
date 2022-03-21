#!/usr/bin/env python3

"""
This Python script loops through the download_urls.json file that was
output from the previous script and downloads the files from the 
Microsoft Symbol Server. We use aiofiles and httpx for asynchronous
work, since this ultimately downloads like 255,000 files and could take
a very long time.

When running, it seemed like this took an hour, though it miss about 17,000
files. 
"""

import json
import os
import sys
import requests
import glob
import time
import urllib3

import asyncio
import httpx
import aiofiles
import aiofiles.os

import aiofiles.ospath

# output_dir = "./binaries"
output_dir = "./newbinaries"

if not os.path.exists(output_dir):
    os.mkdir(output_dir)


async def process_url(client, queue):

    while True:
        count, url, outputname = await queue.get()

        # outputname = url.split("/")[-2] + "_" + line.split("/")[-1]

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


num_downloaded = 0


async def main():
    global num_downloaded

    # Number of concurrent tasks
    NTASKS = 300
    limits = httpx.Limits(max_connections=NTASKS + 10)

    download_urls_filename = "download_urls.json"

    j = json.load(open(download_urls_filename))

    async with httpx.AsyncClient(limits=limits, timeout=20) as client:
        # Build background tasks
        queue = asyncio.Queue()
        tasks = [asyncio.create_task(process_url(client, queue)) for _ in range(NTASKS)]

        for binary_filename in j:
            for sha256hash in j[binary_filename]:

                if j[binary_filename][sha256hash]:
                    url = j[binary_filename][sha256hash]

                    save_filename = f"{sha256hash}_{binary_filename}"
                    save_path = os.path.join(output_dir, save_filename)

                    downloaded = False
                    if await aiofiles.ospath.exists(save_path):
                        if await aiofiles.ospath.getsize(save_path) > 0:
                            # print(f"NOT downloading {save_filename}")
                            downloaded = True
                        else:
                            num_downloaded += 1
                            print(
                                f"{num_downloaded}: EMPTY {save_filename}, re-downloading..."
                            )
                            downloaded = False

                    if not downloaded:
                        await queue.put((0, url, save_path))

        await queue.join()

        for task in tasks:
            task.cancel()
            try:
                await task
            except:
                pass


if __name__ == "__main__":
    asyncio.run(main())

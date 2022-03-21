# Windows File Integrity

> John Hammond

------------------------

## What is this?


This is an attempt to collect as much information as possible on binaries that ship with native installations of Microsoft Windows operating systems. 

## What is in this repo?

This repository hosts files and code that as an archived library for information on native Windows binaries.

Information that IS stored in this repository:

* Python scripts to parse files from Winbindex and download them from the Microsoft Symbol Server
* Golang code to extract extra enrichment data from the binaries
* Compressed JSON data for each binary file referenced by the binary's SHA256 hash

Information that is NOT stored in this repository:

* The binary files themselves

## File Structure

```
wfi
├─── data    (the xz compressed json data for all binaries)
│
├─── scripts (python scripts for Winbindex & MS Symbol Server)
│
└─── enrichment (golang code to add details to binaries)
```
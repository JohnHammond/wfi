# masshash

> John Hammond | November 26th, 2022

--------------------------

Hashing Windows files to add enrichment to Winbindex data.

## Setup

```bash
go mod init wfi
go mod tidy
```

## Usage

```bash
$ go run wfi.go -h

Usage of C:\Users\johnh\AppData\Local\Temp\go-build320018341\b001\exe\wfi.exe:
  -d string
        Binary search directory (default "./binaries")
  -n int
        Number of worker routines to use (default 8)
  -o string
        Output folder to dump XZ compressed JSON files (default "./data")
  -w string
        Winbindex JSON directory (default "./winbindex")
```


```bash
go run wfi.go -d ../scripts/staging_binaries -w ../scripts/winbindex_json -o ../data
```
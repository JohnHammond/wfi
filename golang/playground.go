package main

import (
	// "archive/zip"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	// "path/filepath"
	"bytes"
	"compress/gzip"
	"strings"
)

func downloadFile(filepath string, url string) (err error) {

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Writer the body to file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}

var WINBINDEX_ZIP_FILE = "winbindex-repo.zip"
var WINBINDEX_DIR = "winbindex_json"
var STAGING_DIR = "staging_binaries"

func main() {

	if _, err := os.Stat(STAGING_DIR); os.IsNotExist(err) {
		if err := os.Mkdir(STAGING_DIR, os.ModePerm); err != nil {
			log.Fatal(err)
		}
	}

	previous_directory := "../data/"
	files, err := ioutil.ReadDir(previous_directory)
	if err != nil {
		log.Fatalf("failed to open previous data dir: %v\n", err)
	}

	var original_hashes []string
	for _, file := range files {
		original_hashes = append(original_hashes, strings.Split(file.Name(), ".")[0])
	}

	fmt.Printf("[+] downloading winbindex repo... ")
	downloadFile("winbindex-repo.zip", "https://github.com/m417z/winbindex/archive/refs/heads/gh-pages.zip")
	fmt.Printf("done!\n")

	var desired_extensions = []string{"exe", "dll", "sys"}

	fmt.Printf("[+] extracting winbindex repo (this will take a minute)... \n")
	if _, err := os.Stat(WINBINDEX_DIR); os.IsNotExist(err) {
		if err := os.Mkdir(WINBINDEX_DIR, os.ModePerm); err != nil {
			log.Fatal(err)
		}
	}
	archive, err := zip.OpenReader(WINBINDEX_ZIP_FILE)
	if err != nil {
		log.Fatalf("[!] failed to extract winbindex repo '%v': %v\n", WINBINDEX_ZIP_FILE, err)
	}
	defer archive.Close()

	for _, f := range archive.File {
		if strings.HasPrefix(f.Name, "winbindex-gh-pages/data/by_filename_compressed/") && strings.HasSuffix(f.Name, ".json.gz") {
			// fmt.Printf("found file: %v\n", f.Name)
			var has_desired_extension = false
			for _, ext := range desired_extensions {
				if strings.HasSuffix(f.Name, fmt.Sprintf("%s.json.gz", ext)) {
					has_desired_extension = true
				}
			}

			if has_desired_extension {
				outputFilePath := filepath.Join(WINBINDEX_DIR, filepath.Base(f.Name))
				outputFile, err := os.OpenFile(outputFilePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
				if err != nil {
					log.Fatalf("[!] failed to create zip output file '%v': %v\n", outputFilePath, err)
				}
				fileInArchive, err := f.Open()
				if err != nil {
					log.Fatalf("[!] failed to read file within zip archive '%v': %v\n", f.Name, err)
				}

				if _, err := io.Copy(outputFile, fileInArchive); err != nil {
					log.Fatalf("[!] failed to write output file when extracting zip '%v': %v\n", outputFilePath, err)
				}

				outputFile.Close()
				fileInArchive.Close()
			}
		}
	}

	fmt.Printf("[+] done! now carving through each file...\n")

	json_files, err := ioutil.ReadDir(WINBINDEX_DIR)
	if err != nil {
		log.Fatalf("failed to open winbindex repo dir: %v\n", err)
	}
}

func cleanup() {
	files_to_remove := []string{
		"winbindex-repo.zip",
	}

	for _, each_file := range files_to_remove {
		err := os.Remove(each_file)
		if err != nil {
			log.Printf("[!] failed to remove file '%v': %v", each_file, err)
		}
	}
}

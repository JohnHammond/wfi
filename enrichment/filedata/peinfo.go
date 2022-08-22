package filedata

import (
	"fmt"
	"github.com/Velocidex/ordereddict"
	"os"
	"path/filepath"
	"wfi/masshash/pe" // from github.com/Velocidex/go-pe
)

type FileData struct {
	Path                            string   `json:"path,omitempty"`
	FileSize                        string   `json:"filesize,omitempty"`
	MD5                             string   `json:"md5,omitempty"`
	SHA1                            string   `json:"sha1,omitempty"`
	SHA256                          string   `json:"sha256,omitempty"`
	MajorImageVersion               string   `json:",omitempty"`
	MinorImageVersion               string   `json:",omitempty"`
	CompanyName                     string   `json:",omitempty"`
	FileDescription                 string   `json:",omitempty"`
	FileVersion                     string   `json:",omitempty"`
	InternalName                    string   `json:",omitempty"`
	LegalCopyright                  string   `json:",omitempty"`
	LegalTrademarks                 string   `json:",omitempty"`
	OriginalFilename                string   `json:",omitempty"`
	ProductName                     string   `json:",omitempty"`
	ProductVersion                  string   `json:",omitempty"`
	IssuerName                      string   `json:",omitempty"`
	SerialNumber                    string   `json:",omitempty"`
	ProgramName                     string   `json:",omitempty"`
	MoreInfoLink                    string   `json:",omitempty"`
	IMAGE_FILE_HEADER_Timestamp     string   `json:",omitempty"`
	IMAGE_DEBUG_DIRECTORY_Timestamp string   `json:",omitempty"`
	SignedTimestamp                 string   `json:",omitempty"`
	SubjectName                     string   `json:",omitempty"`
	Imports                         []string `json:",omitempty"`
	Exports                         []string `json:",omitempty"`
	ImpHash                         string   `json:",omitempty"`
}

func GetPEInfo(filePath string) (*FileData, *os.File) {

	filedata := &FileData{}

	f, err := os.OpenFile(filePath, os.O_RDONLY, 0600)
	if err != nil {
		fmt.Printf("failed to open file: %v\n", filePath)
	}
	// defer f.Close()

	if filepath.Ext(filePath) == ".exe" || filepath.Ext(filePath) == ".dll" {

		// Optimized paged read of binary
		reader, err := pe.NewPagedReader(f, 4096, 100)
		if err != nil {
			// fmt.Printf("failed to get binary page\n")
		}

		// Parse PE file
		pe_file, err := pe.NewPEFile(reader)
		if err != nil {
			// log.Fatalf("failed to get pe parser for %v", filePath)
			return filedata, f
		}

		versionInfo := pe_file.AsDict()
		peprofile := pe.NewPeProfile()
		debug := peprofile.IMAGE_DEBUG_DIRECTORY(reader, 0)
		fileheader := peprofile.IMAGE_FILE_HEADER(reader, 0)

		filedata.IMAGE_DEBUG_DIRECTORY_Timestamp = debug.TimeDateStamp().String()
		filedata.IMAGE_FILE_HEADER_Timestamp = fileheader.TimeDateStamp().String()
		filedata.CompanyName = pe.GetString(versionInfo, "VersionInformation.CompanyName")
		filedata.FileDescription = pe.GetString(versionInfo, "VersionInformation.FileDescription")
		filedata.FileVersion = pe.GetString(versionInfo, "VersionInformation.FileVersion")
		filedata.InternalName = pe.GetString(versionInfo, "VersionInformation.InternalName")
		filedata.LegalCopyright = pe.GetString(versionInfo, "VersionInformation.LegalCopyright")
		filedata.LegalTrademarks = pe.GetString(versionInfo, "VersionInformation.LegalTrademarks")
		filedata.OriginalFilename = pe.GetString(versionInfo, "VersionInformation.OriginalFilename")
		filedata.ProductName = pe.GetString(versionInfo, "VersionInformation.ProductName")
		filedata.ProductVersion = pe.GetString(versionInfo, "VersionInformation.ProductVersion")

		filedata.Imports = pe.GetAny(versionInfo, "Imports").([]string)
		filedata.Exports = pe.GetAny(versionInfo, "Exports").([]string)
		filedata.ImpHash = pe_file.ImpHash()

		pkcs7_obj, err := pe.ParseAuthenticode(pe_file)
		if err == nil {
			// filedata.Signed = "true"
			signer := pe.PKCS7ToOrderedDict(pkcs7_obj)
			filedata.IssuerName = pe.GetString(signer, "Signer.IssuerName")
			filedata.SerialNumber = pe.GetString(signer, "Signer.SerialNumber")
			filedata.ProgramName = pe.GetString(signer, "Signer.AuthenticatedAttributes.ProgramName")
			filedata.MoreInfoLink = pe.GetString(signer, "Signer.AuthenticatedAttributes.MoreInfo")
			filedata.SignedTimestamp = pe.GetString(signer, "Signer.AuthenticatedAttributes.SigningTime")
			filedata.SubjectName = pe.GetString(signer, "Signer.Subject")
		} else {
			err = nil // reset err to continue
			// filedata.Signed = "false"
			// Signature not found on PE, let's try to find a corresponding CAT file
			output := ordereddict.NewDict().
				Set("Filename", filePath).
				Set("ProgramName", "").
				Set("PublisherLink", "").
				Set("MoreInfoLink", "").
				Set("SerialNumber", "").
				Set("IssuerName", "").
				Set("SubjectName", "").
				Set("Timestamp", "").
				Set("Trusted", "untrusted").
				Set("_ExtraInfo", "") // Only populated with verbose = TRUE

			cat_file, err := pe.VerifyCatalogSignature(f, filePath, output)
			if err == nil {
				_ = pe.ParseCatFile(cat_file, output, false)
				// filedata.Signed = "true"
				filedata.IssuerName = pe.GetString(output, "IssuerName")
				filedata.SerialNumber = pe.GetString(output, "SerialNumber")
				filedata.ProgramName = pe.GetString(output, "ProgramName")
				filedata.MoreInfoLink = pe.GetString(output, "MoreInfoLink")
				filedata.SignedTimestamp = pe.GetString(output, "Timestamp")
				filedata.SubjectName = pe.GetString(output, "SubjectName")
			}
		}
	}
	return filedata, f

}

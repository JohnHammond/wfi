package pe

import (
	peutil "debug/pe"
	velocidex "github.com/Velocidex/go-pe"
	"io"
	"os"
)

func OriginalFilename(filehandle *os.File) (string, error) {

	reader := io.ReaderAt(filehandle)
	pefile, err := velocidex.NewPEFile(reader)
	if err != nil {
		return "", err // propogate errors
	}

	ofilename, success := pefile.VersionInformation["OriginalFilename"]
	if !success {
		return "", err // propogate errors
	}

	return ofilename, nil
}

func ImageVersions(filename string) (uint16, uint16, error) {

	f, err := peutil.Open(filename)
	if err != nil {
		return 0, 0, err
	}

	optionalHeader := f.OptionalHeader
	var majorImageVersion uint16
	var minorImageVersion uint16

	switch optionalHeader.(type) {

	case *peutil.OptionalHeader64:
		majorImageVersion = optionalHeader.(*peutil.OptionalHeader64).MajorImageVersion
		minorImageVersion = optionalHeader.(*peutil.OptionalHeader64).MinorImageVersion
	case *peutil.OptionalHeader32:
		majorImageVersion = optionalHeader.(*peutil.OptionalHeader32).MajorImageVersion
		minorImageVersion = optionalHeader.(*peutil.OptionalHeader32).MinorImageVersion
	case nil:
		return 0, 0, nil
	}

	return majorImageVersion, minorImageVersion, nil
}

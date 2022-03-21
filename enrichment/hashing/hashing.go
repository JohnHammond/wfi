package hashing

import (
	"bufio"
	"crypto/md5"
	// "crypto/sha1"
	// "crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	// "math"
	"os"
	// "time"

	"github.com/JohnHammond/masshash/slowhash/sha1"
	"github.com/JohnHammond/masshash/slowhash/sha256"
)

const (
	spamSumLength = uint64(64)
	minBlockSize  = uint64(3)
)

const FileDetailsTimeFormat = "2006-01-02 15:04:05 MST"

var (
	h         = map[string]hash.Hash{}
	fileChunk = minBlockSize
)

func GetSHA256(f *os.File) (sha256hash string, err error) {

	hashes, err := GetFileHashes(f)
	if nil != err {
		return "", err
	}

	return hashes.SHA256, nil
}

const filechunk = 8192 // we settle for 8KB

type FileDetailsT struct {
	CreateTime string
	ModTime    string
	Size       int64
}

type HashInfo struct {
	Written int64  `json:"bytes_written"`
	MD5     string `json:"md5"`
	SHA1    string `json:"sha1"`
	SHA256  string `json:"sha256"`
}

// computeFileHashes computes all the hashes for a file
func computeFileHashes(rd io.Reader) (HashInfo, error) {
	md5 := md5.New()
	sha1 := sha1.New()
	sha256 := sha256.New()

	// creates a multiplexer Writer object that will duplicate all write
	// operations when copying data from source into all different hashing algorithms
	// at the same time
	multiWriter := io.MultiWriter(md5, sha1, sha256)

	hashes := HashInfo{}
	var err error
	// Using a buffered reader, this will write to the writer multiplexer
	// so we only traverse through the file once, and can calculate all hashes
	// in a single byte buffered scan pass.
	if hashes.Written, err = io.Copy(multiWriter, rd); err != nil {
		return hashes, err
	}

	hashes.MD5 = hex.EncodeToString(md5.Sum(nil))
	hashes.SHA1 = hex.EncodeToString(sha1.Sum(nil))
	hashes.SHA256 = hex.EncodeToString(sha256.Sum(nil))

	return hashes, nil
}

// computeSha256 returns the SHA 256 of the file. An empty string
// indicates an error
func computeSha256(rd io.Reader) (string, error) {
	sha256 := sha256.New()

	if bytesWritten, err := io.Copy(sha256, rd); err != nil {
		return "", err
	} else if bytesWritten == 0 {
		return "", fmt.Errorf("Computing SHA256 did not write any bytes")
	}
	return hex.EncodeToString(sha256.Sum(nil)), nil
}

// hashSource is an interface to allow testing of the verify hash
// functionality
type hashSource interface {
	Rewind() error
	AsFile() *os.File
}

// runtimeHashSource is the runtime implementation of the hashSource
// interface. It is just an *os.File
type runtimeHashSource struct {
	*os.File
}

// implement that hashSource interface for the runtimeHashsource

// AsFile casts the HashSource into a *os.File
func (hs runtimeHashSource) AsFile() *os.File {
	return hs.File
}

// Rewind seeks to the beginning of the file.
func (hs runtimeHashSource) Rewind() error {
	_, err := hs.Seek(0, 0)
	return err
}

// GetFileHashes is the externally visible function. Takes an os.File
// pointer, wraps it in the interface and calls the internal helper
// function.
func GetFileHashes(rd *os.File) (hashes HashInfo, err error) {
	return getFileHashes(runtimeHashSource{rd})
}

// getFileHashes is the internal function that does all the heavy
// lifting. It takes and interface as the hash source so that we can
// test.
func getFileHashes(rd hashSource) (HashInfo, error) {
	var hashes HashInfo
	err := rd.Rewind()
	if nil != err {
		return hashes, err
	}

	// For optimum speed, Getpagesize returns the underlying system's memory page size.
	pagesize := os.Getpagesize()

	// wraps the Reader object into a new buffered reader to read the files in chunks
	// and buffering them for performance.
	reader := bufio.NewReaderSize(rd.AsFile(), pagesize)

	// calculate the hashes
	hashes, err = computeFileHashes(reader)
	if err != nil {
		return hashes, err
	} else if hashes.Written == 0 {
		err = fmt.Errorf("computeFileHashes did not hash any bytes")
		return hashes, err
	}

	return hashes, err
}

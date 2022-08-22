/*
   Fork of https://github.com/Velocidex/go-pe
   No changes have been made, only forked the repo internaly to pull in
   latest changes not inluded in go module release.

   Apache 2.0 License
*/

package pe

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"

	"github.com/Velocidex/ordereddict"
)

// Exported API

type PagedReader struct {
	reader   io.ReaderAt
	pagesize int64
	lru      *LRU
}

type Section struct {
	Perm       string `json:"Perm"`
	Name       string `json:"Name"`
	FileOffset int64  `json:"FileOffset"`
	VMA        uint64 `json:"VMA"`
	RVA        uint64 `json:"RVA"`
	Size       int64  `json:"Size"`
}

type FileHeader struct {
	Machine          string `json:"Machine"`
	TimeDateStamp    string `json:"TimeDateStamp"`
	TimeDateStampRaw uint32 `json:"TimeDateStampRaw"`
	Characteristics  uint16 `json:"Characteristics"`
	ImageBase        uint64 `json:"ImageBase"`
}

type PEFile struct {
	mu sync.Mutex

	dos_header *IMAGE_DOS_HEADER
	nt_header  *IMAGE_NT_HEADERS

	// Used to resolve RVA to file offsets.
	rva_resolver *RVAResolver

	// The file offset to the resource section.
	resource_base int64

	FileHeader FileHeader `json:"FileHeader"`
	GUIDAge    string     `json:"GUIDAge"`
	PDB        string     `json:"PDB"`
	Sections   []*Section `json:"Sections"`

	imports  []string
	exports  []string
	forwards []string
}

func (self *PEFile) VersionInformation() *ordereddict.Dict {
	return GetVersionInformation(self.nt_header, self.rva_resolver,
		self.resource_base)
}

// Delay calculating these until absolutely necessary.
func (self *PEFile) Imports() []string {
	self.mu.Lock()
	defer self.mu.Unlock()

	if self.imports == nil {
		self.imports = GetImports(self.nt_header, self.rva_resolver)
	}
	return self.imports
}

// Delay calculating these until absolutely necessary.
func (self *PEFile) Exports() []string {
	self.mu.Lock()
	defer self.mu.Unlock()

	if self.exports == nil {
		self.forwards = []string{}
		self.exports = []string{}

		export_desc := self.nt_header.ExportDirectory(self.rva_resolver)
		if export_desc != nil {
			for _, desc := range self.nt_header.ExportTable(self.rva_resolver) {
				if desc.Forwarder != "" {
					self.forwards = append(self.forwards, desc.Forwarder)
				} else if desc.Name == "" {
					self.exports = append(self.exports,
						fmt.Sprintf("%s:#%d", desc.DLLName, desc.Ordinal))
				} else {
					self.exports = append(self.exports,
						fmt.Sprintf("%s:%s", desc.DLLName, desc.Name))
				}
			}
		}
	}
	return self.exports
}

func (self *PEFile) Forwards() []string {
	self.mu.Lock()
	defer self.mu.Unlock()

	if self.forwards == nil {
		self.mu.Unlock()
		self.Exports()
		self.mu.Lock()
	}

	return self.forwards
}

func (self PEFile) Members() []string {
	return []string{
		"FileHeader", "GUIDAge", "PDB", "Sections", "VersionInformation",
		"Imports", "Exports", "Forwards",
	}
}

func (self PEFile) AsDict() *ordereddict.Dict {
	return ordereddict.NewDict().
		Set("FileHeader", self.FileHeader).
		Set("GUIDAge", self.GUIDAge).
		Set("PDB", self.PDB).
		Set("Sections", self.Sections).
		Set("VersionInformation", self.VersionInformation()).
		Set("Imports", self.Imports()).
		Set("Exports", self.Exports()).
		Set("Forwards", self.Forwards())
}

var _sanitized_imp_name = regexp.MustCompile("(.ocx|.sys|.dll)$")

// Calculate the import table hash
// https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html
func (self *PEFile) ImpHash() string {
	imports := self.Imports()
	normalized_imports := make([]string, 0, len(imports))

	for _, imp := range imports {
		imp = strings.ToLower(imp)
		parts := strings.SplitN(imp, "!", 2)
		if len(parts) == 0 {
			continue
		}

		// Remove extensions
		dll := _sanitized_imp_name.ReplaceAllString(parts[0], "")
		normalized_imports = append(normalized_imports,
			fmt.Sprintf("%s.%s", dll, parts[1]))
	}

	// Join all the imports with a , and take their hash.
	data := strings.Join(normalized_imports, ",")
	return fmt.Sprintf("%x", md5.Sum([]byte(data)))
}

func (self *PEFile) GetMessages() []*Message {
	resource_section := self.nt_header.SectionByName(".rsrc")
	if resource_section != nil {
		resource_base := int64(resource_section.PointerToRawData())
		for _, entry := range self.nt_header.ResourceDirectory(
			self.rva_resolver).Entries() {
			if entry.NameString(resource_base) == "RT_MESSAGETABLE" {
				for _, child := range entry.Traverse(resource_base) {
					// Rebase the reader on the resource.
					reader := io.NewSectionReader(child.Reader,
						int64(self.rva_resolver.GetFileAddress(
							child.OffsetToData())),
						int64(child.DataSize()))

					header := child.Profile.MESSAGE_RESOURCE_DATA(
						reader, 0)

					return header.Messages()
				}
			}
		}
	}
	return nil
}

func GetVersionInformation(
	nt_header *IMAGE_NT_HEADERS,
	rva_resolver *RVAResolver,
	resource_base int64) *ordereddict.Dict {
	result := ordereddict.NewDict()

	resourceDirectory := nt_header.ResourceDirectory(rva_resolver)
	if resource_base == 0 {
		resource_base = resourceDirectory.Offset
	}

	// Find the RT_VERSION resource.
	for _, entry := range resourceDirectory.Entries() {

		if entry.NameString(resource_base) == "RT_VERSION" {
			for _, child := range entry.Traverse(resource_base) {
				vs_info := child.Profile.VS_VERSIONINFO(
					child.Reader,
					int64(rva_resolver.GetFileAddress(
						child.OffsetToData())))

				for _, child := range vs_info.Children() {
					for _, string_table := range child.StringTable() {
						for _, resource_string := range string_table.
							ResourceStrings() {
							result.Set(resource_string.Key(),
								resource_string.Value())
						}

					}
				}

			}
		}

	}

	return result
}

func NewPEFile(reader io.ReaderAt) (*PEFile, error) {

	profile := NewPeProfile()
	dos_header := profile.IMAGE_DOS_HEADER(reader, 0)
	if dos_header.E_magic() != 0x5a4d {
		return nil, errors.New("Invalid IMAGE_DOS_HEADER")
	}

	nt_header := dos_header.NTHeader()
	if nt_header.Signature() != 0x4550 {
		return nil, errors.New("Invalid IMAGE_NT_HEADERS")
	}

	rva_resolver := NewRVAResolver(nt_header)

	// Get the base address of the resource section.
	resource_section := nt_header.SectionByName(".rsrc")
	resource_base := int64(resource_section.PointerToRawData())

	file_header := nt_header.FileHeader()
	rsds := nt_header.RSDS(rva_resolver)

	result := &PEFile{
		dos_header:    dos_header,
		nt_header:     nt_header,
		rva_resolver:  rva_resolver,
		resource_base: resource_base,
		FileHeader: FileHeader{
			Machine:          file_header.Machine().Name,
			TimeDateStamp:    file_header.TimeDateStamp().String(),
			Characteristics:  file_header.Characteristics(),
			TimeDateStampRaw: file_header.TimeDateStampRaw(),
			ImageBase:        rva_resolver.ImageBase,
		},
		GUIDAge: rsds.GUIDAge(),
		PDB:     rsds.Filename(),
	}

	for _, section := range nt_header.Sections() {
		rva := uint64(section.VirtualAddress())
		result.Sections = append(result.Sections, &Section{
			Perm:       section.Permissions(),
			Name:       section.Name(),
			FileOffset: int64(section.PointerToRawData()),
			RVA:        rva,
			VMA:        rva + rva_resolver.ImageBase,
			Size:       int64(section.SizeOfRawData()),
		})

	}

	return result, nil
}

func (self *PagedReader) ReadAt(buf []byte, offset int64) (int, error) {
	buf_idx := 0
	for {
		// How much is left in this page to read?
		to_read := int(self.pagesize - offset%self.pagesize)

		// How much do we need to read into the buffer?
		if to_read > len(buf)-buf_idx {
			to_read = len(buf) - buf_idx
		}

		// Are we done?
		if to_read == 0 {
			return buf_idx, nil
		}

		var page_buf []byte

		page := offset - offset%self.pagesize
		cached_page_buf, pres := self.lru.Get(int(page))
		if !pres {
			// Read this page into memory.
			page_buf = make([]byte, self.pagesize)
			_, err := self.reader.ReadAt(page_buf, page)
			if err != nil && err != io.EOF {
				return buf_idx, err
			}

			self.lru.Add(int(page), page_buf)
		} else {
			page_buf = cached_page_buf.([]byte)
		}

		// Copy the relevant data from the page.
		page_offset := int(offset % self.pagesize)
		copy(buf[buf_idx:buf_idx+to_read],
			page_buf[page_offset:page_offset+to_read])

		offset += int64(to_read)
		buf_idx += to_read
	}
}

func NewPagedReader(reader io.ReaderAt, pagesize int64, cache_size int) (*PagedReader, error) {
	// By default 10mb cache.
	cache, err := NewLRU(cache_size, nil)
	if err != nil {
		return nil, err
	}

	return &PagedReader{
		reader:   reader,
		pagesize: pagesize,
		lru:      cache,
	}, nil
}

// Returns the containing dict for a nested dict. This allows fetching
// a key using dot notation.
func _get(dict *ordereddict.Dict, key string) (*ordereddict.Dict, string) {
	components := strings.Split(key, ".")
	// Only a single component, return the dict.
	if len(components) == 1 {
		return dict, components[0]
	}

	// Iterate over all but the last component fetching the nested
	// dicts. If any of these are not present or not a dict,
	// return an empty containing dict.
	for _, member := range components[:len(components)-1] {
		result, pres := dict.Get(member)
		if !pres {
			return ordereddict.NewDict(), ""
		}
		nested, ok := result.(*ordereddict.Dict)
		if !ok {
			return ordereddict.NewDict(), ""
		}
		dict = nested
	}

	return dict, components[len(components)-1]
}

func GetString(dict *ordereddict.Dict, key string) string {
	subdict, last := _get(dict, key)
	res, _ := subdict.GetString(last)
	return res
}

func GetAny(dict *ordereddict.Dict, key string) interface{} {
	subdict, last := _get(dict, key)
	res, _ := subdict.Get(last)
	return res
}

package main

// Kudos to Caleb's baseline code

import (
  "bytes"
  "encoding/json" // used to serialize json
  "flag"          //  used for command-line arguments
  "fmt"           // used for output
  gabs "github.com/Jeffail/gabs/v2"
  "github.com/ulikunitz/xz" // used to write compressed
  "io"
  "io/fs"
  "log"
  "os"
  "path"
  "path/filepath"
  "strings"
  "sync" // used for concurrency
  "wfi/filedata"
)

var winbindex_dir *string // global
var json_dir string       // global
var binary_dir *string    // global
var output_path string    // global

func write_json_to_xz(message string, out_filename string) {

  // Define a buffer to store compressed xz bytes
  var xz_bytes bytes.Buffer

  // Prepare the xz writeer
  w, err := xz.NewWriter(&xz_bytes)
  if err != nil {
    fmt.Printf("failed to create xz writer: %v", err)
    return
  }

  // Write the JSON to xz
  if _, err := io.WriteString(w, message); err != nil {
    fmt.Printf("failed to write json to xz bytes: %v", err)
    return
  }
  // Close the xz writer
  if err := w.Close(); err != nil {
    log.Fatalf("w.Close error %s", err)
  }

  // Create out the xz output file
  file_w, err := os.Create(path.Join(output_path, out_filename))
  if err != nil {
    fmt.Printf("failed to open xz output file: %v", err)
    return
  }
  if _, err := file_w.Write(xz_bytes.Bytes()); err != nil {
    fmt.Printf("failed to write xz output file: %v", err)
    return
  }

  // Close the output file
  if err := file_w.Close(); err != nil {
    log.Fatalf("closing file output error %s", err)
  }
}

func process_file(hash_filename string) {
  if _, err := os.Stat(hash_filename); os.IsNotExist(err) {
    log.Printf("hash_filename %v does not exist", hash_filename)
    return
  }

  file_basename := filepath.Base(hash_filename)
  underscore_pieces := strings.Split(file_basename, "_")
  sha256_hash := underscore_pieces[0]
  filename := strings.Join(underscore_pieces[1:], "_")

  winbindex_json_file := path.Join(json_dir, filename+".json")

  // Do masshash things:
  data, handle := filedata.GetPEInfo(hash_filename) // Retrieve a struct and a file handle
  handle.Close()

  if _, err := os.Stat(winbindex_json_file); os.IsNotExist(err) {
    log.Printf("winbindex_json_file %v does not exist", winbindex_json_file)
    return
  } else {

    json, err := gabs.ParseJSONFile(winbindex_json_file)
    if err != nil {
      log.Fatalf("could not create JSON parser: %v", err)
    }

    // Add the new data from masshash
    json.Set(data, sha256_hash, "enrichment")
    json.Set(filename, sha256_hash, "basename")

    write_json_to_xz(json.Search(sha256_hash).String(), sha256_hash+".json.xz")
  }
}

// Receive file paths and do some work on each, pushing results data to the output
// channel as they are complete.
func worker(files <-chan string, output chan<- filedata.FileData, wg *sync.WaitGroup) {
  defer wg.Done()

  for file := range files {
    // each_extension := strings.Split(*extensions, ",")
    process_file(file)
    // output <- *data
  }
}

// Collect data from all the workers into a central array and dump to the
// requested output stream.
func dumper(output_path string, output <-chan filedata.FileData, wg *sync.WaitGroup) {
  defer wg.Done()

  var results []filedata.FileData

  // Take files from the workers and add them to our in-memory list
  for data := range output {
    results = append(results, data)
  }

  if output_path == "-" {
    // Marshal the data to stdout
    encoder := json.NewEncoder(os.Stdout)
    encoder.Encode(results)
  } else {

    // Define a buffer to store compressed xz bytes
    var xz_bytes bytes.Buffer

    // Retrieve the JSON bytes
    json_bytes, err := json.Marshal(results)
    if err != nil {
      log.Fatalf("failed to marshal JSON data: %v", err)
    }

    // Prepare the xz writeer
    w, err := xz.NewWriter(&xz_bytes)
    if err != nil {
      fmt.Printf("failed to create xz writer: %v", err)
      return
    }

    // Write the JSON to xz
    if _, err := io.WriteString(w, string(json_bytes)); err != nil {
      fmt.Printf("failed to write json to xz bytes: %v", err)
      return
    }
    // Close the xz writer
    if err := w.Close(); err != nil {
      log.Fatalf("w.Close error %s", err)
    }

    // Create out the xz output file
    file_w, err := os.Create(output_path)
    if err != nil {
      fmt.Printf("failed to open xz output file: %v", err)
      return
    }
    if _, err := file_w.Write(xz_bytes.Bytes()); err != nil {
      fmt.Printf("failed to write xz output file: %v", err)
      return
    }

    // Close the output file
    if err := file_w.Close(); err != nil {
      log.Fatalf("closing file output error %s", err)
    }
  }
}

func main() {

  out_path := flag.String("o", "./data", "Output folder to dump XZ compressed JSON files")
  binary_dir := flag.String("d", "./binaries", "Binary search directory")
  winbindex_dir := flag.String("w", "./winbindex", "Winbindex JSON directory")

  nworkers := flag.Int("n", 8, "Number of worker routines to use")
  flag.Parse()

  if _, err := os.Stat(*binary_dir); os.IsNotExist(err) {
    log.Fatalf("binary dir '%v' does not exist. please supply path to binaries with -d.\n", *binary_dir)
    os.Exit(1)
  }

  if _, err := os.Stat(*winbindex_dir); os.IsNotExist(err) {
    log.Fatalf("winbindex json dir '%v' does not exist. please supply path to winbindex json files with -w\n", *winbindex_dir)
    os.Exit(1)
  }
  json_dir = filepath.Clean(*winbindex_dir)

  if _, err := os.Stat(*out_path); os.IsNotExist(err) {
    os.Mkdir(*out_path, 0655)
  }
  output_path = filepath.Clean(*out_path)

  // Allow us to wait on all the routines
  var worker_group sync.WaitGroup

  // Queue of up to 1000 files
  files := make(chan string, 1000)
  results := make(chan filedata.FileData, 1000)

  // Start nWorkers background workers all using
  // the same file queue
  for i := 0; i < *nworkers; i++ {
    worker_group.Add(1)
    go worker(files, results, &worker_group)
  }

  // Iterate through all files and add them to the queue
  // Once all are added, close the channel
  err := filepath.WalkDir(*binary_dir, func(path string, d fs.DirEntry, err error) error {
    // Propogate errors
    if err != nil {
      return err
    }

    // We don't care about directories
    if d.IsDir() {
      return nil
    }

    // Queue the file to be examined
    files <- path

    // No errors
    return nil
  })

  // All files are processed; this triggers the workers to exit
  close(files)

  // Wait for worker routines to finish
  worker_group.Wait()

  // Let the user know if there were any errors during tree walk
  if err != nil {
    fmt.Printf("error while walking tree: %v\n", err)
  }
}

package core

import (
  "crypto/sha1"
  "fmt"
  "io"
  "path/filepath"
  "regexp"
  "strings"
)

const (
  TypeSimple  = "simple"
  TypePattern = "pattern"

  PartExtension = "extension"
  PartFilename  = "filename"
  PartPath      = "path"
)

var skippableExtensions = []string{".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".psd", ".xcf"}
var skippablePathIndicators = []string{"node_modules/", "vendor/bundle", "vendor/cache"}

type MatchFile struct {
  Path      string
  Filename  string
  Extension string
}

func (f *MatchFile) IsSkippable() bool {
  ext := strings.ToLower(f.Extension)
  path := strings.ToLower(f.Path)
  for _, skippableExt := range skippableExtensions {
    if ext == skippableExt {
      return true
    }
  }
  for _, skippablePathIndicator := range skippablePathIndicators {
    if strings.Contains(path, skippablePathIndicator) {
      return true
    }
  }
  return false
}

type Finding struct {
  Id              string
  FilePath        string
  Action          string
  Description     string
  Comment         string
  RepositoryOwner string
  RepositoryName  string
  CommitHash      string
  CommitMessage   string
  CommitAuthor    string
  FileUrl         string
  CommitUrl       string
  RepositoryUrl   string
}

func (f *Finding) setupUrls() {
  f.RepositoryUrl = fmt.Sprintf("https://github.com/%s/%s", f.RepositoryOwner, f.RepositoryName)
  f.FileUrl = fmt.Sprintf("%s/blob/%s/%s", f.RepositoryUrl, f.CommitHash, f.FilePath)
  f.CommitUrl = fmt.Sprintf("%s/commit/%s", f.RepositoryUrl, f.CommitHash)
}

func (f *Finding) generateID() {
  h := sha1.New()
  io.WriteString(h, f.FilePath)
  io.WriteString(h, f.Action)
  io.WriteString(h, f.RepositoryOwner)
  io.WriteString(h, f.RepositoryName)
  io.WriteString(h, f.CommitHash)
  io.WriteString(h, f.CommitMessage)
  io.WriteString(h, f.CommitAuthor)
  f.Id = fmt.Sprintf("%x", h.Sum(nil))
}

func (f *Finding) Initialize() {
  f.setupUrls()
  f.generateID()
}

type Signature interface {
  Match(file MatchFile) bool
  Description() string
  Comment() string
}

type SimpleSignature struct {
  part        string
  match       string
  description string
  comment     string
}

type PatternSignature struct {
  part        string
  match       *regexp.Regexp
  description string
  comment     string
}

func (s SimpleSignature) Match(file MatchFile) bool {
  var haystack *string
  switch s.part {
  case PartPath:
    haystack = &file.Path
  case PartFilename:
    haystack = &file.Filename
  case PartExtension:
    haystack = &file.Extension
  default:
    return false
  }

  return (s.match == *haystack)
}

func (s SimpleSignature) Description() string {
  return s.description
}

func (s SimpleSignature) Comment() string {
  return s.comment
}

func (s PatternSignature) Match(file MatchFile) bool {
  var haystack *string
  switch s.part {
  case PartPath:
    haystack = &file.Path
  case PartFilename:
    haystack = &file.Filename
  case PartExtension:
    haystack = &file.Extension
  default:
    return false
  }

  return s.match.MatchString(*haystack)
}

func (s PatternSignature) Description() string {
  return s.description
}

func (s PatternSignature) Comment() string {
  return s.comment
}

func NewMatchFile(path string) MatchFile {
  _, filename := filepath.Split(path)
  extension := filepath.Ext(path)
  return MatchFile{
    Path:      path,
    Filename:  filename,
    Extension: extension,
  }
}

var Signatures = []Signature{
  SimpleSignature{
    part:        PartExtension,
    match:       ".pem",
    description: "Potential cryptographic private key",
    comment:     "",
  },
  SimpleSignature{
    part:        PartExtension,
    match:       ".log",
    description: "Log file",
    comment:     "Log files can contain secret HTTP endpoints, session IDs, API keys and other goodies",
  },
}

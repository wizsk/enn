package main

import (
	"time"
)

const (
	progName           = "enn"
	progVersion        = "v0.1"
	configFileName     = "enn-conf"
	firstRunFileName   = "first-ran"
	verifyIntervalDays = 7
	minPasswordLength  = 8
	timeFormat         = "3:04 PM 02/01/06"
)

var (
	buildTime    string
	gitCommit    string
	gitCommitMsg string
)

// Config holds the application configuration
type Config struct {
	NotesDir   string    `json:"notes_dir"`
	Key        []byte    `json:"key"`
	LastVerify time.Time `json:"last_verify"`
}

// FileManifest tracks file states
type FileManifest struct {
	// key is the file name. eg. foo.md
	Files map[string]FileInfo `json:"files"`
}

type FileInfo struct {
	// Encrypted    bool      `json:"encrypted"`
	Hash         string    `json:"hash"`
	LastModified time.Time `json:"last_modified"`
}

// App holds application state
type App struct {
	config       Config
	configDir    string
	configFile   string
	logFile      string
	manifestFile string
	noColor      bool
}

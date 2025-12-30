package main

import "time"

const (
	verifyIntervalDays = 7
	minPasswordLength  = 1
	minSaltLength      = 1
	pbkdf2Iterations   = 100000
	aesKeySize         = 32 // AES-256
)

// Config holds the application configuration
type Config struct {
	NotesDir   string    `json:"notes_dir"`
	Password   []byte    `json:"password"`
	LastVerify time.Time `json:"last_verify"`
}

// FileManifest tracks file states
type FileManifest struct {
	// key is the file name. eg. foo.md
	Files map[string]FileInfo `json:"files"`
}

type FileInfo struct {
	// Name         string    `json:"name"` // fo.md
	Hash         string    `json:"hash"`
	LastModified time.Time `json:"last_modified"`
	Encrypted    bool      `json:"encrypted"`
}

// App holds application state
type App struct {
	configDir    string
	configFile   string
	logFile      string
	manifestFile string
	config       Config
	// password     []byte
	noColor bool
}

package main

import "time"

const (
	verifyIntervalDays = 7
	minPasswordLength  = 12
	pbkdf2Iterations   = 100000
	aesKeySize         = 32 // AES-256
)

// Config holds the application configuration
type Config struct {
	NotesDir   string    `json:"notes_dir"`
	LastVerify time.Time `json:"last_verify"`
}

// FileManifest tracks file states
type FileManifest struct {
	Files map[string]FileInfo `json:"files"`
}

type FileInfo struct {
	Hash         string    `json:"hash"`
	LastModified time.Time `json:"last_modified"`
	Encrypted    bool      `json:"encrypted"`
}

// App holds application state
type App struct {
	configDir    string
	configFile   string
	passwordFile string
	logFile      string
	manifestFile string
	config       Config
	password     []byte
	noColor      bool
}

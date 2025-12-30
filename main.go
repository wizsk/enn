package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
)

func main() {
	// Command line flags
	confDir := flag.String("conf-dir", "", "Config dir (default: ~/.config)")
	decryptFlag := flag.String("decrypt", "", "Decrypt a specific file (provide path to .enc file)")
	decryptAllFlag := flag.Bool("decrypt-all", false, "Decrypt all .enc files in notes directory")
	outputFlag := flag.String("output", "", "Output file for decryption (default: stdout for single file)")
	noColorFlag := flag.Bool("no-color", false, "Disable colored output")
	flag.Parse()

	app := &App{
		noColor:   *noColorFlag,
		configDir: *confDir,
	}

	// Disable colors globally if flag is set
	if app.noColor {
		color.NoColor = true
	}

	if err := app.initialize(); err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}

	// First time setup - just configure, don't do anything
	if _, err := os.Stat(app.configFile); os.IsNotExist(err) {
		if err := app.firstTimeSetup(); err != nil {
			app.errorMsg(fmt.Sprintf("ERROR: %v", err))
			os.Exit(1)
		}
		app.success("Setup complete! Run without flags to encrypt notes, or use --decrypt-all to decrypt them.")
		return
	}

	// Load config and password for all other operations
	if err := app.loadConfig(); err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}
	if err := app.loadPassword(); err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}

	// Decrypt all mode
	if *decryptAllFlag {
		if err := app.decryptAllMode(); err != nil {
			app.errorMsg(fmt.Sprintf("ERROR: %v", err))
			os.Exit(1)
		}
		return
	}

	// Decrypt single file mode
	if *decryptFlag != "" {
		if err := app.decryptMode(*decryptFlag, *outputFlag); err != nil {
			app.errorMsg(fmt.Sprintf("ERROR: %v", err))
			os.Exit(1)
		}
		return
	}

	// Normal backup/encrypt mode
	if err := app.run(); err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}
}

func (app *App) initialize() error {
	if app.configDir == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		app.configDir = filepath.Join(homeDir, ".config", "enn-files")
	}

	app.configFile = filepath.Join(app.configDir, "config.json")
	app.passwordFile = filepath.Join(app.configDir, "password")
	app.logFile = filepath.Join(app.configDir, "backup.log")

	// Create config directory
	if err := os.MkdirAll(app.configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	return nil
}

func (app *App) run() error {
	fmt.Println("==========================================")
	fmt.Println("  Encrypt & Backup Notes")
	fmt.Println("==========================================")
	fmt.Println()

	app.log("Starting backup process")

	// Check password verification
	if err := app.checkPasswordVerification(); err != nil {
		return err
	}

	// Initialize git repository
	if err := app.initGitRepo(); err != nil {
		return err
	}

	// Set manifest file path
	app.manifestFile = filepath.Join(app.config.NotesDir, ".manifest.json")

	// Load or create manifest
	manifest, err := app.loadManifest()
	if err != nil {
		return err
	}

	// Encrypt notes
	if err := app.encryptNotes(manifest); err != nil {
		return err
	}

	// Save manifest
	if err := app.saveManifest(manifest); err != nil {
		return err
	}

	// Verify backup
	if err := app.verifyBackup(); err != nil {
		return err
	}

	// Git commit
	if err := app.gitCommit(); err != nil {
		return err
	}

	// Show status
	app.showStatus()

	app.success("Backup completed successfully!")
	app.log("Backup process completed")

	return nil
}

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
	confDirFlag := flag.String("conf-dir", "", "Config dir (default: ~/.config/"+configFileName+")")
	forceEncryptFlag := flag.Bool("force-enc", false, "Enecrypt all .md files in notes directory even if .enc exists")
	decryptAllFlag := flag.Bool("dec-all", false, "Decrypt all .enc files in notes directory")
	decNewOrModifiedFlag := flag.Bool("check-dec", false, "cehck and decrypt new/modified notes")
	decryptFileFlag := flag.String("dec", "", "Decrypt a specific file (provide path to .enc file)")
	outputFlag := flag.String("out", "", "Output file for --dec flag (default: stdout for single file)")
	confirmPassFlag := flag.Bool("check-pass", false, "confirm password")
	changePassFlag := flag.Bool("change-pass", false, "chagne password")
	noColorFlag := flag.Bool("no-color", false, "Disable colored output")
	cleanFlag := flag.Bool("clean", false, "cleanup or delete deleted notes")
	gpushFlag := flag.Bool("push", false, "git push")
	gpullFlag := flag.Bool("pull", false, "git pull and decrypt new or modified files")

	flag.Usage = func() { fmt.Println(optionsTxt()) }
	flag.Parse()

	app := &App{
		noColor:   *noColorFlag,
		configDir: *confDirFlag,
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
		app.success("Setup complete! Run without flags to encrypt notes, or use --dec-all to decrypt them.")
		return
	}

	// Load config and password for all other operations
	if err := app.loadConfig(); err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}

	if *gpushFlag {
		if err := app.gitPush(); err != nil {
			app.errorMsg(fmt.Sprintf("ERROR: %v", err))
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *gpullFlag {
		if err := app.gitPull(); err != nil {
			app.errorMsg(fmt.Sprintf("ERROR: %v", err))
			os.Exit(1)
		}
		if err := app.checkAndDecNotes(); err != nil {
			app.errorMsg(fmt.Sprintf("ERROR: %v", err))
			os.Exit(1)
		}
		os.Exit(0)

	}

	if *decNewOrModifiedFlag {
		if err := app.checkAndDecNotes(); err != nil {
			app.errorMsg(fmt.Sprintf("ERROR: %v", err))
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *cleanFlag {
		if err := app.cleanNotes(); err != nil {
			app.errorMsg(fmt.Sprintf("ERROR: %v", err))
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *changePassFlag {
		app.changePass()
		os.Exit(0)
	}

	if *confirmPassFlag {
		if err := app.checkPasswordVerification(true); err != nil {
			app.errorMsg(fmt.Sprintf("ERROR: %v", err))
			os.Exit(1)
		}
		os.Exit(0)
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
	if *decryptFileFlag != "" {
		if err := app.decryptMode(*decryptFileFlag, *outputFlag); err != nil {
			app.errorMsg(fmt.Sprintf("ERROR: %v", err))
			os.Exit(1)
		}
		return
	}

	// Normal backup/encrypt mode
	if err := app.run(*forceEncryptFlag); err != nil {
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
		app.configDir = filepath.Join(homeDir, ".config", configFileName)
	}

	// Create config directory
	if err := os.MkdirAll(app.configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	app.configFile = filepath.Join(app.configDir, "config.json")
	app.logFile = filepath.Join(app.configDir, "enn.log")

	return nil
}

func (app *App) run(forceEnc bool) error {
	fmt.Println("==========================================")
	fmt.Println("  Encrypt & Backup Notes")
	fmt.Println("==========================================")
	fmt.Println()

	app.log("Starting backup process")

	// Check password verification
	if err := app.checkPasswordVerification(false); err != nil {
		return err
	}

	// Initialize git repository
	if err := app.initGitRepo(); err != nil {
		return err
	}

	// Load or create manifest
	var manifest *FileManifest
	if forceEnc {
		manifest = &FileManifest{make(map[string]FileInfo)}
	} else {
		m, err := app.loadManifest()
		if err != nil {
			return err
		}
		manifest = m
	}

	// Encrypt notes
	newManifest, err := app.encryptNotes(manifest)
	if err != nil {
		return err
	}

	if manifest.Equal(newManifest) {
		app.info("No new changes was made nothing to commit")
	} else {
		// Save manifest
		if err := app.saveManifest(newManifest); err != nil {
			return err
		}

		// Verify backup
		if newManifest == nil || len(newManifest.Files) == 0 {
			app.warning("No files found to encrypt. Skipping verifications")
		} else {
			if err := app.verifyBackup(); err != nil {
				return err
			}
		}

		// Git commit
		if err := app.gitCommit(""); err != nil {
			return err
		}
	}

	// Show status
	app.showStatus()

	app.success("Backup completed successfully!")
	app.log("Backup process completed")

	fmt.Println()
	app.warnPossibleDeletedNotes()

	return nil
}

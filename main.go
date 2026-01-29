package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
)

var (
	encryptAndPush bool
)

func main() {
	// Command line flags
	confDirFlag := flag.String("conf-dir", "", "Config dir (default: ~/.config/"+configFileName+")")
	cngConfFlag := flag.Bool("edit-conf", false, "change configuration")
	forceEncryptFlag := flag.Bool("force-enc", false, "Enecrypt all .md files in notes directory even if .enc exists")
	decryptAllFlag := flag.Bool("dec-all", false, "Decrypt all .enc files in notes directory")
	decNewOrModifiedFlag := flag.Bool("check-dec", false, "cehck and decrypt new/modified notes")
	decryptFileFlag := flag.String("dec", "", "Decrypt a specific file (provide path to .enc file)")
	outputFlag := flag.String("out", "", "Output file for --dec flag (default: stdout for single file)")
	confirmPassFlag := flag.Bool("check-pass", false, "confirm password")
	changePassFlag := flag.Bool("change-pass", false, "chagne password")
	noColorFlag := flag.Bool("no-color", false, "Disable colored output")
	cleanFlag := flag.Bool("clean", false, "cleanup or delete deleted notes")
	flag.BoolVar(&encryptAndPush, "ep", false, "encrypt and git push")
	gpushFlag := flag.Bool("push", false, "git push")
	gpullFlag := flag.Bool("pull", false, "git pull and decrypt new or modified files")
	showStatusFlag := flag.Bool("status", false, "print status")
	verstionFlag := flag.Bool("version", false, "print version")

	flag.Usage = func() { fmt.Println(optionsTxt(coloredStyler())) }
	flag.Parse()

	if *verstionFlag {
		printVersion()
		os.Exit(0)
	}

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
		app.success("Setup complete! Now run without any flags")
		return
	}

	// Load config and password for all other operations
	if err := app.loadConfig(); err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}

	if *showStatusFlag {
		app.showStatus()
		os.Exit(0)
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
		if err := app.cleanNotes(); err != nil {
			app.errorMsg(fmt.Sprintf("ERROR: %v", err))
			os.Exit(1)
		}
		os.Exit(0)
	}

	if *cngConfFlag {
		fmt.Printf("Current notes directory: %s\n", app.config.NotesDir)
		if confirmPromt("Do you want to change it?", confirmPromtDefaultNone) {
			newNotesDir, err := getNotesDir()
			if err != nil {
				app.errorMsg(fmt.Sprintf("ERROR: %v", err))
				os.Exit(1)
			}
			if newNotesDir == app.config.NotesDir {
				fmt.Printf("New and previous notes directory are the same: %s\n", app.config.NotesDir)
			} else {
				app.config.NotesDir = newNotesDir
				if err = app.saveConfig(); err != nil {
					app.errorMsg(fmt.Sprintf("ERROR: %v", err))
					os.Exit(1)
				}
				os.Remove(filepath.Join(app.configDir, firstRunFileName))
				fmt.Printf("Notes directory changed to: %s\n", app.config.NotesDir)
			}
		}

		if confirmPromt("Do you want to change the password?", confirmPromtDefaultNone) {
			app.changePass()
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
		confDir, err := os.UserConfigDir()
		if err != nil {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("failed to get home directory: %w", err)
			}
			confDir = filepath.Join(homeDir, ".config")
		}
		app.configDir = filepath.Join(confDir, configFileName)
	}

	// Create config directory
	if err := os.MkdirAll(app.configDir, 0700); err != nil && !os.IsExist(err) {
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

	fRunFilePath := filepath.Join(app.configDir, firstRunFileName)
	isFRun := ival(os.Stat(fRunFilePath)) != nil
	if isFRun {
		if f, err := os.Create(fRunFilePath); err == nil {
			f.Close()
		}

		if ef, _ := filepath.Glob(filepath.Join(app.config.NotesDir, "*.enc")); len(ef) > 0 {
			fmt.Println()
			app.info("It seems like you are running for the first time after setting up notes directory")
			app.info("There are %d encrypted notes", len(ef))
			if confirmPromt("Would you like to decrypt all of them?", confirmPromtDefaultYes) {
				return app.decryptAllMode()
			}
		}

	}

	// Check password verification
	if err := app.checkPasswordVerification(false); err != nil {
		return err
	}

	// Initialize git repository
	isNewInitGit, err := app.initGitRepo()
	_ = isNewInitGit
	if err != nil {
		return err
	}

	// Load or create manifest
	var manifest FileManifest
	if forceEnc {
		manifest = FileManifest{make(map[string]FileInfo)}
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

	if !manifest.Equal(newManifest) {
		if err := app.saveManifest(newManifest); err != nil {
			return err
		}

		if len(newManifest.Files) == 0 {
			app.warning("No files encrypted files found. Skipping verifications")
		} else {
			if err := app.verifyBackup(); err != nil {
				return err
			}
		}
	}

	if err := app.gitCommit("", newManifest); err != nil {
		return err
	}

	// Show status
	app.showStatus()

	app.success("Backup completed successfully!")
	app.log("Backup process completed")

	if encryptAndPush {
		fmt.Println()
		app.info("Pusing")
		if err := app.gitPush(); err != nil {
			app.errorMsg("While pushing: %s", err)
		}
	}

	fmt.Println()
	app.warnPossibleDeletedNotes()

	return nil
}

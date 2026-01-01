package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

func genKeyFromPassword(confirm bool) ([]byte, error) {
	var password string

	// Ask for password
	for {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, fmt.Errorf("genPassword: reading password: %w", err)
		}
		fmt.Println()
		password = strings.TrimSpace(string(passwordBytes))

		// Check password length
		if len(password) < minPasswordLength {
			fmt.Printf("Password must be at least %d characters\n", minPasswordLength)
			continue
		}
		break
	}

	if confirm {
		for {
			fmt.Print("Confirm password: ")
			confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
			if err != nil {
				return nil, fmt.Errorf("genPassword: reading confirmation password: %w", err)
			}
			fmt.Println()

			// Check if passwords match
			if strings.TrimSpace(string(confirmBytes)) != password {
				fmt.Println("Passwords don't match. Try again.")
				continue
			}
			break
		}
	}

	const (
		argonTime = 3
		argonMem  = 64 * 1024 // 64 MiB
		argonPar  = 4
		keyLen    = 32 // AES-256
	)

	key := argon2.IDKey(
		[]byte(password),
		[]byte(appSalt),
		argonTime,
		argonMem,
		argonPar,
		keyLen,
	)

	return key, nil
}

func (app *App) changePass() {
	{
		encF, _ := filepath.Glob(filepath.Join(app.config.NotesDir, "*.enc"))
		mdF, _ := filepath.Glob(filepath.Join(app.config.NotesDir, "*.md"))
		if len(encF) != len(mdF) {
			app.errorMsg(fmt.Sprintf("ERROR: .enc file count: %d but .md file count: %d", len(encF), len(mdF)))
			color.Red(".enc files are more than .md files meaning some files maybe encrypted with the old key")
			color.Red("You might want to look into that before proceeding")
			if !confirmPromt("Do you want to proceed anyways?", confirmPromtDefaultNo) {
				os.Exit(1)
			}
		}
	}

	nk, err := genKeyFromPassword(true)
	if err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}

	app.config.Key = nk
	app.config.LastVerify = time.Now()
	if err = app.saveConfig(); err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}

	manifest := FileManifest{make(map[string]FileInfo)}
	manifest, err = app.encryptNotes(manifest)
	if err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}

	if err = app.saveManifest(manifest); err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}

	if len(manifest.Files) == 0 {
		app.warning("No files found to encrypt. Skipping verifications and git commit")
	} else {
		// Verify backup
		if err := app.verifyBackup(); err != nil {
			app.errorMsg(fmt.Sprintf("ERROR: %v", err))
			os.Exit(1)
		}

	}

	// Git commit
	if err := app.gitCommit(fmt.Sprintf("Password changed at %s", time.Now().Format(timeFormat)), manifest); err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}

	app.showStatus()
}

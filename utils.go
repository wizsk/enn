package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

func (app *App) verifyBackup() error {
	app.log("Verifying backup integrity")

	encFiles, err := filepath.Glob(filepath.Join(app.config.NotesDir, "*.enc"))
	if err != nil {
		return err
	}

	if len(encFiles) == 0 {
		app.warning("No encrypted files to verify")
		return nil
	}

	verified := 0
	failed := 0

	for _, encFile := range encFiles {
		originalFile := strings.TrimSuffix(encFile, ".enc")

		if _, err := os.Stat(originalFile); err == nil {
			// Original exists, verify match
			if err := app.verifyEncryption(originalFile, encFile); err != nil {
				app.warning(fmt.Sprintf("Verification mismatch: %s", filepath.Base(encFile)))
				failed++
				continue
			}
		} else {
			// Just verify decryption works
			if _, err := app.decryptFile(encFile); err != nil {
				app.warning(fmt.Sprintf("Cannot decrypt: %s", filepath.Base(encFile)))
				failed++
				continue
			}
		}

		verified++
	}

	if failed == 0 {
		app.success(fmt.Sprintf("All %d encrypted files verified successfully", verified))
	} else {
		return fmt.Errorf("%d files failed verification out of %d total", failed, verified+failed)
	}

	return nil
}

func (app *App) showStatus() {
	fmt.Println()
	fmt.Println("==========================================")
	fmt.Println("  Backup Status")
	fmt.Println("==========================================")
	fmt.Printf("Notes directory: %s\n", app.config.NotesDir)
	fmt.Printf("Config directory: %s\n", app.configDir)

	mdFiles, _ := filepath.Glob(filepath.Join(app.config.NotesDir, "*.md"))
	encFiles, _ := filepath.Glob(filepath.Join(app.config.NotesDir, "*.enc"))

	fmt.Printf("Markdown files: %d\n", len(mdFiles))
	fmt.Printf("Encrypted files: %d\n", len(encFiles))

	cmd := exec.Command("git", "rev-list", "--count", "HEAD")
	cmd.Dir = app.config.NotesDir
	output, err := cmd.Output()
	if err == nil {
		fmt.Printf("Total commits: %s", string(output))
	}

	daysSince := time.Since(app.config.LastVerify).Hours() / 24
	fmt.Printf("Last password verification: %.0f days ago\n", daysSince)

	fmt.Println("==========================================")
	fmt.Println()
}

func (app *App) fileHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash), nil
}

func (app *App) copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func (app *App) log(message string) {
	logMsg := fmt.Sprintf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), message)
	f, err := os.OpenFile(app.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(logMsg)
}

func (app *App) success(message string) {
	color.Green("✓ %s", message)
	app.log("SUCCESS: " + message)
}

func (app *App) warning(message string) {
	color.Yellow("⚠ %s", message)
	app.log("WARNING: " + message)
}

func (app *App) info(message string) {
	color.Cyan("ℹ %s", message)
}

func (app *App) errorMsg(message string) {
	color.Red("✗ %s", message)
	app.log("ERROR: " + message)
}

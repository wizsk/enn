package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

func (app *App) firstTimeSetup() error {
	fmt.Println("==========================================")
	fmt.Println("  First Time Setup")
	fmt.Println("==========================================")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	// Get notes directory
	app.info("Enter the full path to your notes directory:")
	fmt.Print("> ")
	notesDir, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read notes directory: %w", err)
	}
	notesDir = strings.TrimSpace(notesDir)

	// Expand ~ to home directory
	if strings.HasPrefix(notesDir, "~") {
		homeDir, _ := os.UserHomeDir()
		notesDir = filepath.Join(homeDir, notesDir[1:])
	}

	// Convert to absolute path
	notesDir, err = filepath.Abs(notesDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	// Verify directory exists
	if _, err := os.Stat(notesDir); os.IsNotExist(err) {
		return fmt.Errorf("directory does not exist: %s", notesDir)
	}

	// Count files
	mdFiles, _ := filepath.Glob(filepath.Join(notesDir, "*.md"))
	encFiles, _ := filepath.Glob(filepath.Join(notesDir, "*.enc"))

	if len(mdFiles) > 0 {
		app.info(fmt.Sprintf("Found %d .md files", len(mdFiles)))
	}
	if len(encFiles) > 0 {
		app.info(fmt.Sprintf("Found %d .enc encrypted files", len(encFiles)))
	}

	if len(mdFiles) == 0 && len(encFiles) == 0 {
		app.warning("No .md or .enc files found in this directory")
		fmt.Print("Continue anyway? (y/n): ")
		response, _ := reader.ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(response)), "y") {
			return fmt.Errorf("setup cancelled")
		}
	}

	// Get password
	fmt.Println()
	app.info(fmt.Sprintf("Enter your encryption password (minimum %d characters):", minPasswordLength))
	app.info("If you're setting up on a new device with encrypted notes, use the SAME password.")

	var password string
	for {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println()

		password = string(passwordBytes)

		if len(password) < minPasswordLength {
			app.errorMsg(fmt.Sprintf("Password must be at least %d characters", minPasswordLength))
			continue
		}

		fmt.Print("Confirm password: ")
		confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println()

		if string(confirmBytes) != password {
			app.errorMsg("Passwords don't match. Try again.")
			continue
		}

		break
	}

	// Save configuration
	app.config = Config{
		NotesDir:   notesDir,
		LastVerify: time.Now(),
	}

	if err := app.saveConfig(); err != nil {
		return err
	}

	app.password = []byte(password)
	if err := app.savePassword(); err != nil {
		return err
	}

	app.success(fmt.Sprintf("Configuration saved to %s", app.configDir))
	fmt.Println()

	return nil
}

func (app *App) loadConfig() error {
	data, err := os.ReadFile(app.configFile)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	if err := json.Unmarshal(data, &app.config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	if _, err := os.Stat(app.config.NotesDir); os.IsNotExist(err) {
		return fmt.Errorf("notes directory no longer exists: %s", app.config.NotesDir)
	}

	return nil
}

func (app *App) saveConfig() error {
	data, err := json.MarshalIndent(app.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(app.configFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

func (app *App) loadPassword() error {
	data, err := os.ReadFile(app.passwordFile)
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	app.password = bytes.TrimSpace(data)
	return nil
}

func (app *App) savePassword() error {
	if err := os.WriteFile(app.passwordFile, app.password, 0600); err != nil {
		return fmt.Errorf("failed to write password: %w", err)
	}
	return nil
}

func (app *App) checkPasswordVerification() error {
	daysSince := time.Since(app.config.LastVerify).Hours() / 24

	if daysSince < verifyIntervalDays {
		return nil
	}

	fmt.Println()
	app.warning(fmt.Sprintf("It's been %.0f days since last password verification", daysSince))
	app.info("Please verify your password:")

	maxAttempts := 3
	for attempt := range maxAttempts {
		fmt.Print("Password: ")
		enteredPassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println()

		if bytes.Equal(bytes.TrimSpace(enteredPassword), app.password) {
			app.success("Password verified!")
			app.config.LastVerify = time.Now()
			if err := app.saveConfig(); err != nil {
				return err
			}
			fmt.Println()
			return nil
		}

		if attempt < maxAttempts-1 {
			app.errorMsg(fmt.Sprintf("Incorrect password. %d attempts remaining.", maxAttempts-attempt-1))
		}
	}

	return fmt.Errorf("password verification failed after %d attempts", maxAttempts)
}

func (app *App) loadManifest() (*FileManifest, error) {
	manifest := &FileManifest{
		Files: make(map[string]FileInfo),
	}

	data, err := os.ReadFile(app.manifestFile)
	if err != nil {
		if os.IsNotExist(err) {
			return manifest, nil
		}
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	if err := json.Unmarshal(data, manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	return manifest, nil
}

func (app *App) saveManifest(manifest *FileManifest) error {
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	if err := os.WriteFile(app.manifestFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

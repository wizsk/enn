package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func (app *App) firstTimeSetup() error {
	fmt.Println("==========================================")
	fmt.Println("  First Time Setup")
	fmt.Println("==========================================")
	fmt.Println()

	notesDir, err := getNotesDir()
	if err != nil {
		return err
	}

	// Get password
	fmt.Println()
	app.info(fmt.Sprintf("Enter your encryption password (minimum %d characters):", minPasswordLength))
	app.info("If you're setting up on a new device with encrypted notes, use the SAME password.")

	key, err := genKeyFromPassword(true)
	if err != nil {
		return err
	}

	// Save configuration
	app.config = Config{
		NotesDir:   notesDir,
		LastVerify: time.Now(),
		Key:        key,
	}

	if err := app.saveConfig(); err != nil {
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

	// Set manifest file path
	app.manifestFile = filepath.Join(app.config.NotesDir, ".manifest.json")
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

func (app *App) checkPasswordVerification(force bool) error {
	if !force {
		daysSince := time.Since(app.config.LastVerify).Hours() / 24

		if daysSince < verifyIntervalDays {
			return nil
		}

		fmt.Println()
		app.warning(fmt.Sprintf("It's been %.0f days since last password verification", daysSince))
	}

	app.info("Please verify your password:")

	maxAttempts := 3
	for attempt := range maxAttempts {
		enteredKey, err := genKeyFromPassword(false)
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}

		// fmt.Printf("%x\n%x\n", enteredPassword, app.config.Password)
		if bytes.Equal(enteredKey, app.config.Key) {
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

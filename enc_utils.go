package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (app *App) decryptAllMode() error {
	fmt.Println("==========================================")
	fmt.Println("  Decrypt All Notes")
	fmt.Println("==========================================")
	fmt.Println()

	app.log("Starting decrypt-all process")

	encFiles, err := filepath.Glob(filepath.Join(app.config.NotesDir, "*.enc"))
	if err != nil {
		return err
	}

	if len(encFiles) == 0 {
		app.warning("No .enc files found to decrypt")
		return nil
	}

	app.info(fmt.Sprintf("Found %d encrypted files", len(encFiles)))
	fmt.Println()

	successCount := 0
	failCount := 0

	for _, encFile := range encFiles {
		filename := filepath.Base(encFile)
		outputFile := strings.TrimSuffix(encFile, ".enc")

		// Check if output file already exists
		if _, err := os.Stat(outputFile); err == nil {
			app.warning(fmt.Sprintf("%s (unencrypted file already exists)", filename))
			p := fmt.Sprintf("Do you want to overwrite %q?", filename)
			if !confirmPromt(p, confirmPromtDefaultNo) {
				continue
			}
		}

		app.info(fmt.Sprintf("Decrypting: %s", filename))

		// Decrypt
		plaintext, err := app.decryptFile(encFile)
		if err != nil {
			app.errorMsg(fmt.Sprintf("Failed to decrypt %s: %v", filename, err))
			failCount++
			continue
		}

		// Write decrypted file
		if err := os.WriteFile(outputFile, plaintext, 0644); err != nil {
			app.errorMsg(fmt.Sprintf("Failed to write %s: %v", filepath.Base(outputFile), err))
			failCount++
			continue
		}

		app.success(fmt.Sprintf("Decrypted: %s → %s", filename, filepath.Base(outputFile)))
		successCount++
	}

	fmt.Println()
	if failCount == 0 {
		app.success(fmt.Sprintf("Successfully decrypted all %d files!", successCount))
	} else {
		app.warning(fmt.Sprintf("Decrypted %d files, %d failed", successCount, failCount))
	}

	app.log(fmt.Sprintf("Decrypt-all completed: %d success, %d failed", successCount, failCount))

	return nil
}

func (app *App) decryptMode(encryptedPath, outputPath string) error {
	// Check if file exists
	if _, err := os.Stat(encryptedPath); os.IsNotExist(err) {
		return fmt.Errorf("file not found: %s", encryptedPath)
	}

	app.info(fmt.Sprintf("Decrypting: %s", encryptedPath))

	// Decrypt file
	plaintext, err := app.decryptFile(encryptedPath)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Write output
	if outputPath != "" {
		if err := os.WriteFile(outputPath, plaintext, 0644); err != nil {
			return fmt.Errorf("failed to write output: %w", err)
		}
		app.success(fmt.Sprintf("Decrypted to: %s", outputPath))
	} else {
		// Write to stdout
		os.Stdout.Write(plaintext)
	}

	return nil
}

func (app *App) verifyEncryption(originalPath, encryptedPath string) error {
	original, err := os.ReadFile(originalPath)
	if err != nil {
		return err
	}

	decrypted, err := app.decryptFile(encryptedPath)
	if err != nil {
		return err
	}

	if !bytes.Equal(original, decrypted) {
		return fmt.Errorf("decrypted content doesn't match original")
	}

	return nil
}

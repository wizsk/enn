package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

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
		app.configDir = filepath.Join(homeDir, ".config", "note-backup-tool")
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
			app.warning(fmt.Sprintf("Skipping %s (unencrypted file already exists)", filename))
			continue
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

func (app *App) initGitRepo() error {
	gitDir := filepath.Join(app.config.NotesDir, ".git")

	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		app.log("Initializing git repository")
		cmd := exec.Command("git", "init")
		cmd.Dir = app.config.NotesDir
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to initialize git: %w", err)
		}
		app.success("Git repository initialized")
	}

	// Create/update .gitignore
	gitignorePath := filepath.Join(app.config.NotesDir, ".gitignore")
	gitignoreContent := `# Ignore all files by default
*

# Allow encrypted files
!*.enc

# Allow git files
!.gitignore
!.gitattributes
!.manifest.json

# Ignore unencrypted notes
*.md
*.txt
*.doc
*.docx
*.pdf

# Ignore temp files
*.tmp
*.swp
*~
.DS_Store
`

	existingContent, err := os.ReadFile(gitignorePath)
	if err == nil && strings.Contains(string(existingContent), "!*.enc") {
		app.info(".gitignore already configured correctly")
	} else {
		if err == nil {
			// Backup existing
			os.WriteFile(gitignorePath+".backup", existingContent, 0644)
		}
		if err := os.WriteFile(gitignorePath, []byte(gitignoreContent), 0644); err != nil {
			return fmt.Errorf("failed to write .gitignore: %w", err)
		}
		app.success("Created/updated .gitignore")
	}

	// Initial commit if needed
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = app.config.NotesDir
	if err := cmd.Run(); err != nil {
		cmd = exec.Command("git", "add", ".gitignore")
		cmd.Dir = app.config.NotesDir
		cmd.Run()

		cmd = exec.Command("git", "commit", "-m", "Initial commit: Setup encrypted notes repository")
		cmd.Dir = app.config.NotesDir
		cmd.Run()
		app.success("Initial commit created")
	}

	return nil
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

func (app *App) encryptNotes(manifest *FileManifest) error {
	app.log("Starting encryption process")

	mdFiles, err := filepath.Glob(filepath.Join(app.config.NotesDir, "*.md"))
	if err != nil {
		return err
	}

	if len(mdFiles) == 0 {
		app.warning("No .md files found")
		return nil
	}

	successCount := 0
	skippedCount := 0

	for _, mdFile := range mdFiles {
		filename := filepath.Base(mdFile)
		encryptedFile := mdFile + ".enc"

		// Get file info
		fileInfo, err := os.Stat(mdFile)
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", filename, err)
		}

		// Calculate hash
		hash, err := app.fileHash(mdFile)
		if err != nil {
			return fmt.Errorf("failed to hash %s: %w", filename, err)
		}

		// Check if encryption is needed
		if oldInfo, exists := manifest.Files[filename]; exists {
			if oldInfo.Hash == hash && oldInfo.Encrypted {
				skippedCount++
				continue
			}
		}

		app.info(fmt.Sprintf("Encrypting: %s", filename))

		// Backup existing encrypted file
		backupFile := encryptedFile + ".backup"
		if _, err := os.Stat(encryptedFile); err == nil {
			if err := app.copyFile(encryptedFile, backupFile); err != nil {
				return fmt.Errorf("failed to backup %s: %w", filename, err)
			}
		}

		// Encrypt file
		if err := app.encryptFile(mdFile, encryptedFile); err != nil {
			os.Remove(encryptedFile)
			if _, err := os.Stat(backupFile); err == nil {
				os.Rename(backupFile, encryptedFile)
			}
			return fmt.Errorf("failed to encrypt %s: %w", filename, err)
		}

		// Verify encryption
		if err := app.verifyEncryption(mdFile, encryptedFile); err != nil {
			os.Remove(encryptedFile)
			if _, err := os.Stat(backupFile); err == nil {
				os.Rename(backupFile, encryptedFile)
			}
			return fmt.Errorf("verification failed for %s: %w", filename, err)
		}

		// Success - remove backup
		os.Remove(backupFile)

		// Update manifest
		manifest.Files[filename] = FileInfo{
			Hash:         hash,
			LastModified: fileInfo.ModTime(),
			Encrypted:    true,
		}

		app.success(fmt.Sprintf("Encrypted and verified: %s", filename))
		successCount++
	}

	if successCount > 0 || skippedCount > 0 {
		app.success(fmt.Sprintf("Encryption summary: %d encrypted, %d unchanged", successCount, skippedCount))
	}

	return nil
}

func (app *App) encryptFile(inputPath, outputPath string) error {
	// Read plaintext
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	// Derive key from password
	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}

	key := pbkdf2.Key(app.password, salt, pbkdf2Iterations, aesKeySize, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Write: salt + ciphertext
	output := append(salt, ciphertext...)

	return os.WriteFile(outputPath, output, 0644)
}

func (app *App) decryptFile(inputPath string) ([]byte, error) {
	// Read encrypted data
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, err
	}

	if len(data) < 32 {
		return nil, fmt.Errorf("invalid encrypted file")
	}

	// Extract salt
	salt := data[:32]
	ciphertext := data[32:]

	// Derive key
	key := pbkdf2.Key(app.password, salt, pbkdf2Iterations, aesKeySize, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
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

func (app *App) gitCommit() error {
	app.log("Starting git commit")

	cmd := exec.Command("git", "add", "*.enc", ".gitignore", ".manifest.json")
	cmd.Dir = app.config.NotesDir
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git add failed: %w", err)
	}

	// Check if there are changes
	cmd = exec.Command("git", "diff", "--cached", "--quiet")
	cmd.Dir = app.config.NotesDir
	if err := cmd.Run(); err == nil {
		app.info("No changes to commit")
		return nil
	}

	// Count encrypted files
	encFiles, _ := filepath.Glob(filepath.Join(app.config.NotesDir, "*.enc"))
	commitMsg := fmt.Sprintf("Backup: %d encrypted files - %s", len(encFiles), time.Now().Format("2006-01-02 15:04:05"))

	cmd = exec.Command("git", "commit", "-m", commitMsg)
	cmd.Dir = app.config.NotesDir
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git commit failed: %w", err)
	}

	app.success(fmt.Sprintf("Git commit created: %s", commitMsg))

	// Show recent commits
	fmt.Println()
	app.info("Recent backups:")
	cmd = exec.Command("git", "log", "--oneline", "-5")
	cmd.Dir = app.config.NotesDir
	cmd.Stdout = os.Stdout
	cmd.Run()
	fmt.Println()

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

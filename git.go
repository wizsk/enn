package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func newCmd(o, e io.Writer, cmd string, args ...string) *exec.Cmd {
	c := exec.Command(cmd, args...)
	c.Stdin = os.Stdin
	c.Stderr = e
	c.Stdout = o
	// c.Stdout = os.Stdout
	// c.Stderr = os.Stderr
	return c
}

func (app *App) initGitRepo() error {
	gitDir := filepath.Join(app.config.NotesDir, ".git")

	buf := new(bytes.Buffer)
	if _, err := os.Stat(gitDir); os.IsNotExist(err) {
		app.log("Initializing git repository")
		buf.Reset()
		cmd := newCmd(buf, buf, "git", "init")
		cmd.Dir = app.config.NotesDir
		if err := cmd.Run(); err != nil {
			fmt.Println(buf.String())
			return fmt.Errorf("failed to initialize git: %w", err)
		}
		app.success("Git repository initialized")
	}

	// Create/update .gitignore
	gitignorePath := filepath.Join(app.config.NotesDir, ".gitignore")
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
		buf.Reset()
		cmd = newCmd(buf, buf, "git", "add", ".gitignore")
		cmd.Dir = app.config.NotesDir
		if err := cmd.Run(); err != nil {
			fmt.Println(buf.String())
			return fmt.Errorf("failed to initialize git: %w", err)
		}

		buf.Reset()
		cmd = newCmd(buf, buf, "git", "commit", "-m", "Initial commit: Setup encrypted notes repository")
		cmd.Dir = app.config.NotesDir
		if err := cmd.Run(); err != nil {
			fmt.Println(buf.String())
			return fmt.Errorf("failed to initialize git: %w", err)
		}
		app.success("Initial commit created")
	}

	return nil
}

func (app *App) gitCommit() error {
	app.log("Starting git commit")

	buf := new(bytes.Buffer)
	cmd := newCmd(buf, buf, "git", "add", "*.enc", ".gitignore", ".manifest.json")
	cmd.Dir = app.config.NotesDir
	if err := cmd.Run(); err != nil {
		fmt.Println(buf.String())
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

	buf.Reset()
	cmd = newCmd(buf, buf, "git", "commit", "-m", commitMsg)
	cmd.Dir = app.config.NotesDir
	if err := cmd.Run(); err != nil {
		fmt.Println(buf.String())
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

func (app *App) gitPush() error {
	cmd := newCmd(os.Stdin, os.Stderr, "git", "push")
	cmd.Dir = app.config.NotesDir
	return cmd.Run()
}

func (app *App) gitPull() error {
	cmd := newCmd(os.Stdin, os.Stderr, "git", "pull")
	cmd.Dir = app.config.NotesDir
	return cmd.Run()
}

const gitignoreContent = `# Ignore all files by default
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

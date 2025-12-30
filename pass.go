package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fatih/color"
)

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

	np, err := genPassword(true)
	if err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}

	app.config.Password = np
	app.config.LastVerify = time.Now()
	if err = app.saveConfig(); err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}

	manifest := &FileManifest{make(map[string]FileInfo)}
	newManifest, err := app.encryptNotes(manifest)
	if err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}

	if err = app.saveManifest(newManifest); err != nil {
		app.errorMsg(fmt.Sprintf("ERROR: %v", err))
		os.Exit(1)
	}
}

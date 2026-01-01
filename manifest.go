package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

func (fm FileManifest) Equal(fm2 FileManifest) bool {
	if fm.Files == nil && fm2.Files == nil {
		return true
	} else if fm.Files == nil || fm2.Files == nil ||
		len(fm.Files) != len(fm2.Files) {
		return false
	}

	for k, v := range fm.Files {
		v2, ok := fm2.Files[k]
		if !ok || v.Hash != v2.Hash ||
			!v.LastModified.Equal(v2.LastModified) {
			return false
		}
	}

	return true
}

func (app *App) warnPossibleDeletedNotes() {
	mdFiles, _ := filepath.Glob(filepath.Join(app.config.NotesDir, "*.md"))
	encFiles, _ := filepath.Glob(filepath.Join(app.config.NotesDir, "*.enc"))

	if len(encFiles) == 0 {
		return
	}

	// mdMap := enc_md_map(mdFiles)
	mdMap := make(map[string]struct{}, len(mdFiles))
	for _, v := range mdFiles {
		v = filepath.Base(v)
		mdMap[v] = struct{}{}
	}

	wr := false
	for _, v := range encFiles {
		v = strings.TrimSuffix(filepath.Base(v), ".enc")
		if _, ok := mdMap[v]; !ok {
			w := fmt.Sprintf("Possible deletion: %s", v)
			app.warning(w)
			wr = true
		}
	}
	if wr {
		app.info("Run --clean command to delete them")
		return
	}
}

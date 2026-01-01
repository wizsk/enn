package main

import "github.com/fatih/color"

func optionsTxt() string {
	b := color.New(color.Bold)
	bu := color.New(color.Bold, color.Underline)
	rb := color.New(color.FgRed, color.Bold)
	return `A program to keep your ` + rb.Sprint("thoughts") + ` safe
` + bu.Sprint("Usage:") + " " + b.Sprint(progName) + ` [OPTIONS]

` + bu.Sprint("Options:") + `
  ` + b.Sprint("--conf-dir") + ` <path>
      Specify config dir (default: ~/.config/` + configFileName + `)
  ` + b.Sprint("--edit-conf") + `
      Change configurations (eg. notes directory path and more)
  ` + b.Sprint("--force-enc") + `
      Enecrypt all notes even if the note is already encryped
  ` + b.Sprint("--dec-all") + `
      Decrypt all encrypted notes
  ` + b.Sprint("--check-dec") + `
      Decrypt new or modified encrypted notes
  ` + b.Sprint("--dec") + ` <path>
      Decrypt a specific file
  ` + b.Sprint("--out") + ` <path>
      Output file for ` + b.Sprint("--dec") + ` flag
  ` + b.Sprint("--check-pass") + `
      test yourself if you remember the password or not
  ` + b.Sprint("--change-pass") + `
      change password
  ` + b.Sprint("--no-color") + `
      Disable colored output
  ` + b.Sprint("--clean") + `
      Cleanup deleted notes
  ` + b.Sprint("--push") + `
      git push
  ` + b.Sprint("--pull") + `
      git pull and decrypt new or modified notes`
}

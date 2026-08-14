// Package web holds the embedded UI assets: HTML templates and static files.
//
// Everything is compiled into the binary so that deployment is a single file
// copy with no asset directory to keep in sync.
package web

import "embed"

// Templates holds the HTML templates.
//
//go:embed templates
var Templates embed.FS

// Static holds files served under /static/.
//
//go:embed static
var Static embed.FS

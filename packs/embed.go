// Package packs embeds the shipped content, so a binary installed on its own
// (the agent, on every platform) carries the checks it is meant to run rather
// than depending on a directory the installers never copied.
package packs

import "embed"

// SCA holds packs/sca/*.yaml.
//
//go:embed sca/*.yaml
var SCA embed.FS

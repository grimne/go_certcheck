package output

import (
	"fmt"
	"io"

	"github.com/grimne/certcheck/internal/cert"
	"github.com/grimne/certcheck/internal/config"
)

// Write outputs certificate info in the specified format
func Write(info *cert.Info, format config.OutputFormat, w io.Writer) error {
	switch format {
	case config.FormatJSON:
		return writeJSON(info, w)
	case config.FormatYAML:
		return writeYAML(info, w)
	case config.FormatTOML:
		return writeTOML(info, w)
	case config.FormatText:
		return writeText(info, w)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

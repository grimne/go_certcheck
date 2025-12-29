package output

import (
	"encoding/json"
	"io"

	"github.com/BurntSushi/toml"
	"github.com/grimne/certcheck/internal/cert"
	"gopkg.in/yaml.v3"
)

func writeJSON(info *cert.Info, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(info)
}

func writeYAML(info *cert.Info, w io.Writer) error {
	enc := yaml.NewEncoder(w)
	defer enc.Close()
	return enc.Encode(info)
}

func writeTOML(info *cert.Info, w io.Writer) error {
	return toml.NewEncoder(w).Encode(info)
}

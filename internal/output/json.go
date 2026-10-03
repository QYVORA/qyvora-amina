package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/QYVORA/qyvora-amina/internal/config"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// JSONRenderer writes the machine-readable format.
//
// This is the format the ecosystem's conformance contract and any pipeline
// consumes, so it is the strictest: no colour, no progress, no banner, and
// stable field names. The document is indented, because a machine format that
// is also readable by a human during an incident costs nothing and is often the
// only format anyone ever looks at.
type JSONRenderer struct{}

func (JSONRenderer) Format() config.Format { return config.FormatJSON }

func (r JSONRenderer) Write(w io.Writer, rep *models.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// HTML escaping is left on. A report contains strings gathered from
	// configuration files and environment variables, and an unescaped "<" in a
	// git remote must not become markup when someone pipes this into a viewer.
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	return nil
}

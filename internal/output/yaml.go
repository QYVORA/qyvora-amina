package output

import (
	"encoding/json"
	"fmt"
	"io"

	yaml "go.yaml.in/yaml/v3"

	"github.com/QYVORA/qyvora-amina/internal/config"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// YAMLRenderer writes the YAML format.
//
// This is the human-diffable machine format: it is what an engineer pastes into
// a ticket and what a pipeline stores to compare against last week's run. The
// emitter is the ecosystem's own yaml.v3 rather than a hand-written one, for
// the same reason the JSON renderer uses encoding/json — the type conversion is
// where YAML documents are most often wrong, and the standard emitter knows
// about the cases ("yes" is a boolean in YAML 1.1, an octal-looking string is a
// number, a multi-line description needs an indentation indicator) that a
// custom writer gets wrong silently.
//
// The report is serialised through JSON tags rather than YAML ones so that the
// two machine formats cannot disagree about a field name. A consumer that reads
// the JSON can read the YAML with the same field names, which is what makes the
// pair interchangeable.
type YAMLRenderer struct{}

func (YAMLRenderer) Format() config.Format { return config.FormatYAML }

func (r YAMLRenderer) Write(w io.Writer, rep *models.Report) error {
	// Round-tripping through JSON first is what guarantees the field names
	// match. yaml.v3 would otherwise use the Go field names, producing a second
	// vocabulary for the same document.
	data, err := json.Marshal(rep)
	if err != nil {
		return fmt.Errorf("prepare yaml report: %w", err)
	}
	// The JSON is decoded into a generic tree before it is re-encoded as YAML.
	// Handing yaml.v3 a json.RawMessage would emit the entire document as one
	// quoted string, which is valid YAML and useless as YAML.
	var tree any
	if err := json.Unmarshal(data, &tree); err != nil {
		return fmt.Errorf("prepare yaml report: %w", err)
	}
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(tree); err != nil {
		return fmt.Errorf("write yaml report: %w", err)
	}
	return enc.Close()
}

package report

import (
	"encoding/json"
	"io"

	"github.com/opencomputinggarage/cargo-scanner/internal/core"
)

func WriteJSON(w io.Writer, r core.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func WriteJSONArray(w io.Writer, reports []core.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(reports)
}

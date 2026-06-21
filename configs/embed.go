package configs

import _ "embed"

// BundleZip contains the built-in baseline configs needed for single-binary runs.
// nuclei-templates are intentionally excluded; `dddd update` manages them on disk.
//
//go:embed bundle.zip
var BundleZip []byte

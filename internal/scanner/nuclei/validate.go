package nuclei

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	protocoltypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

// ValidateTemplate performs strict offline parsing, not full compilation:
// compiling JavaScript requests would execute their init code before scanning.
func ValidateTemplate(path, root string) error {
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular template file: %s", path)
	}
	parser := templates.NewParser()
	catalog := disk.NewCatalog(root)
	filter, err := templates.NewTagFilter(&templates.TagFilterConfig{})
	if err != nil {
		return err
	}
	if _, err = parser.LoadTemplate(path, filter, nil, catalog); err != nil {
		return err
	}
	value, err := parser.ParseTemplate(path, catalog)
	if err != nil {
		return err
	}
	tpl := value.(*templates.Template)
	if tpl.Type() == protocoltypes.InvalidProtocol {
		return fmt.Errorf("template has no supported protocol requests")
	}
	for _, request := range tpl.RequestsHTTP {
		if err := request.Operators.Compile(); err != nil {
			return fmt.Errorf("HTTP operators: %w", err)
		}
		for name, value := range request.Payloads {
			resource, ok := value.(string)
			if !ok || strings.ContainsRune(resource, '\n') {
				continue
			}
			if !payloadResourceExists(resource, filepath.Dir(path), root) {
				return fmt.Errorf("HTTP payload %s: resource not found: %s", name, resource)
			}
		}
	}
	return nil
}

// Match the shared dictionaries under the template root without executing a request.
func payloadResourceExists(resource, dir, root string) bool {
	regular := func(path string) bool { s, err := os.Stat(path); return err == nil && s.Mode().IsRegular() }
	if filepath.IsAbs(resource) {
		return regular(resource)
	}
	if regular(filepath.Join(root, resource)) {
		return true
	}
	for {
		if regular(filepath.Join(dir, resource)) {
			return true
		}
		rel, err := filepath.Rel(root, dir)
		if err != nil || rel == "." || !filepath.IsLocal(rel) {
			return false
		}
		dir = filepath.Dir(dir)
	}
}

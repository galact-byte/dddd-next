package nuclei

import (
	nucleilib "github.com/projectdiscovery/nuclei/v3/lib"
	pkgtypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
	"reflect"
	"testing"
)

func TestAuditInteractshPreservesScanOptions(t *testing.T) {
	for _, mode := range []string{"baseline", "ni", "iserver", "itoken"} {
		t.Run(mode, func(t *testing.T) {
			opts := DefaultOptions()
			opts.Templates = []string{"audit-local-template.yaml"}
			opts.Tags = []string{"audit"}
			opts.Severities = "critical"
			switch mode {
			case "ni":
				opts.NoInteractsh = true
			case "iserver":
				opts.InteractshServer = "https://oob.invalid"
			case "itoken":
				opts.InteractshToken = "fake-audit-token"
			}
			engine := &nucleilib.NucleiEngine{}
			if err := nucleilib.WithOptions(&pkgtypes.Options{})(engine); err != nil {
				t.Fatal(err)
			}
			for _, option := range buildSDKOptions(opts) {
				if err := option(engine); err != nil {
					t.Fatal(err)
				}
			}
			got := engine.Options()
			if got.NoInteractsh != opts.NoInteractsh || got.InteractshURL != opts.InteractshServer || got.InteractshToken != opts.InteractshToken {
				t.Fatalf("Interactsh settings were lost: disabled=%v server=%q", got.NoInteractsh, got.InteractshURL)
			}
			t.Logf("templates=%v tags=%v severities=%v concurrency=%d silent=%v", got.Templates, got.Tags, got.Severities, got.TemplateThreads, got.Silent)
			if !reflect.DeepEqual([]string(got.Templates), opts.Templates) || !reflect.DeepEqual([]string(got.Tags), opts.Tags) || len(got.Severities) != 1 || got.TemplateThreads != opts.Concurrency || !got.Silent {
				t.Error("设置 Interactsh 参数后模板、筛选和并发配置应保留")
			}
		})
	}
}

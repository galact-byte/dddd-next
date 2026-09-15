package updater

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

type binaryFixture struct {
	tag, asset, payload, checksums string
	certificate                    string
	size                           int
	status                         map[string]int
	redirect                       string
	requests                       []string
	authorization                  map[string]string
	draft, prerelease              bool
}

func newBinaryFixture(t *testing.T) (*BinaryUpdater, *binaryFixture) {
	t.Helper()
	t.Setenv("GITHUB_TOKEN", "")
	f := &binaryFixture{
		tag: "v0.1.49", asset: "dddd-next_0.1.49_windows_amd64.exe", payload: "new executable",
		status: make(map[string]int), authorization: make(map[string]string),
	}
	f.size = len(f.payload)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests = append(f.requests, r.URL.Path)
		f.authorization[r.URL.Path] = r.Header.Get("Authorization")
		if status := f.status[r.URL.Path]; status != 0 {
			w.WriteHeader(status)
			return
		}
		switch r.URL.Path {
		case "/latest":
			if f.redirect != "" {
				http.Redirect(w, r, f.redirect, http.StatusFound)
				return
			}
			base := "https://" + r.Host
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": f.tag, "draft": f.draft, "prerelease": f.prerelease,
				"assets": []map[string]any{
					{"name": f.asset, "browser_download_url": base + "/binary", "size": f.size},
					{"name": "checksums.txt", "browser_download_url": base + "/checksums"},
				},
			})
		case "/redirected":
			fmt.Fprint(w, `{"tag_name":"v0.1.48"}`)
		case "/checksums":
			if f.checksums != "" {
				fmt.Fprint(w, f.checksums)
			} else {
				fmt.Fprintf(w, "%x  %s\n", sha256.Sum256([]byte(f.payload)), f.asset)
			}
		case "/binary":
			fmt.Fprint(w, f.payload)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	f.certificate = hex.EncodeToString(server.Certificate().Raw)
	target := filepath.Join(t.TempDir(), "renamed scanner.exe")
	if err := os.WriteFile(target, []byte("old executable"), 0755); err != nil {
		t.Fatal(err)
	}
	u := NewBinaryUpdater("0.1.48")
	u.releaseURL = server.URL + "/latest"
	testClient := server.Client()
	testClient.CheckRedirect = u.client.CheckRedirect
	u.client = testClient
	u.targetPath = target
	u.progress = io.Discard
	u.goos, u.goarch = "windows", "amd64"
	return u, f
}

func TestBinaryUpdateReplacesExecutable(t *testing.T) {
	for _, platform := range []struct{ goos, arch, asset string }{
		{"windows", "amd64", "dddd-next_0.1.49_windows_amd64.exe"},
		{"linux", "amd64", "dddd-next_0.1.49_linux_amd64"},
		{"linux", "arm64", "dddd-next_0.1.49_linux_arm64"},
	} {
		t.Run(platform.goos+"/"+platform.arch, func(t *testing.T) {
			u, f := newBinaryFixture(t)
			u.goos, u.goarch, f.asset = platform.goos, platform.arch, platform.asset
			result, err := u.Update(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if !result.Updated || result.Version != "0.1.49" {
				t.Fatalf("result = %+v", result)
			}
			assertBinaryContent(t, u.targetPath, f.payload)
		})
	}
}

func TestBinaryUpdateFailureRetainsOriginal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*BinaryUpdater, *binaryFixture)
		want  string
	}{
		{"checksum mismatch", func(_ *BinaryUpdater, f *binaryFixture) { f.checksums = fmt.Sprintf("%064d  %s", 0, f.asset) }, "wrong checksum"},
		{"missing checksum", func(_ *BinaryUpdater, f *binaryFixture) { f.checksums = "abcd  different-file" }, "missing SHA-256"},
		{"invalid checksum", func(_ *BinaryUpdater, f *binaryFixture) { f.checksums = "zz  " + f.asset }, "invalid SHA-256"},
		{"duplicate checksum", func(_ *BinaryUpdater, f *binaryFixture) {
			line := fmt.Sprintf("%x  %s\n", sha256.Sum256([]byte(f.payload)), f.asset)
			f.checksums = line + line
		}, "duplicate checksum"},
		{"short download", func(_ *BinaryUpdater, f *binaryFixture) { f.size++ }, "size mismatch"},
		{"oversize download", func(_ *BinaryUpdater, f *binaryFixture) { f.size-- }, "exceeds expected size"},
		{"oversize asset", func(_ *BinaryUpdater, f *binaryFixture) { f.size = maxBinarySize + 1 }, "invalid binary size"},
		{"rate limit", func(_ *BinaryUpdater, f *binaryFixture) { f.status["/latest"] = 403 }, "HTTP 403"},
		{"checksum download fails", func(_ *BinaryUpdater, f *binaryFixture) { f.status["/checksums"] = 404 }, "HTTP 404"},
		{"binary download fails", func(_ *BinaryUpdater, f *binaryFixture) { f.status["/binary"] = 502 }, "HTTP 502"},
		{"unsupported platform", func(u *BinaryUpdater, _ *binaryFixture) { u.goarch = "386" }, "no binary for windows/386"},
		{"invalid current version", func(u *BinaryUpdater, _ *binaryFixture) { u.version = "dev" }, "invalid current version"},
		{"invalid tag", func(_ *BinaryUpdater, f *binaryFixture) { f.tag = "not-a-version" }, "invalid stable release"},
		{"draft", func(_ *BinaryUpdater, f *binaryFixture) { f.draft = true }, "invalid stable release"},
		{"prerelease", func(_ *BinaryUpdater, f *binaryFixture) { f.prerelease = true }, "invalid stable release"},
		{"prerelease tag", func(_ *BinaryUpdater, f *binaryFixture) { f.tag = "v0.1.49-rc.1" }, "invalid stable release"},
		{"insecure URL", func(u *BinaryUpdater, _ *binaryFixture) {
			u.releaseURL = strings.Replace(u.releaseURL, "https:", "http:", 1)
		}, "invalid HTTPS"},
		{"HTTP redirect rejected", func(_ *BinaryUpdater, f *binaryFixture) { f.redirect = "http://example.invalid/binary" }, "must use HTTPS"},
		{"untrusted TLS certificate", func(u *BinaryUpdater, _ *binaryFixture) { u.client = NewBinaryUpdater(u.version).client }, "certificate"},
		{"missing executable", func(u *BinaryUpdater, _ *binaryFixture) { u.targetPath += ".missing" }, "resolve executable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, f := newBinaryFixture(t)
			target := u.targetPath
			tc.setup(u, f)
			result, err := u.Update(context.Background())
			if err == nil || !strings.Contains(err.Error(), tc.want) || result.Updated {
				t.Fatalf("result = %+v, error = %v; want %q", result, err, tc.want)
			}
			assertBinaryContent(t, target, "old executable")
		})
	}
}

func TestBinaryReplacementFailureRetainsOriginal(t *testing.T) {
	for _, suffix := range []string{".new", ".old"} {
		t.Run(suffix, func(t *testing.T) {
			u, _ := newBinaryFixture(t)
			blocker := filepath.Join(filepath.Dir(u.targetPath), "."+filepath.Base(u.targetPath)+suffix)
			if err := os.Mkdir(blocker, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(blocker, "occupied"), []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			result, err := u.Update(context.Background())
			if err == nil || result.Updated || !strings.Contains(err.Error(), "original executable retained") {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
			assertBinaryContent(t, u.targetPath, "old executable")
		})
	}
}

func TestBinaryCheckDoesNotDownloadOrModify(t *testing.T) {
	u, f := newBinaryFixture(t)
	result, err := u.Check(context.Background())
	if err != nil || !result.Available || result.Updated || result.Version != "0.1.49" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	if strings.Join(f.requests, ",") != "/latest" {
		t.Fatalf("unexpected requests: %v", f.requests)
	}
	assertBinaryContent(t, u.targetPath, "old executable")
}

func TestBinaryUpdateTokenOnlySentToReleaseAPI(t *testing.T) {
	u, f := newBinaryFixture(t)
	t.Setenv("GITHUB_TOKEN", "  test-update-token  ")
	result, err := u.Update(context.Background())
	if err != nil || !result.Updated {
		t.Fatalf("update = %+v, %v", result, err)
	}
	if f.authorization["/latest"] != "Bearer test-update-token" {
		t.Fatal("Release API did not receive the configured token")
	}
	for _, path := range []string{"/binary", "/checksums"} {
		if f.authorization[path] != "" {
			t.Fatalf("token leaked to download path %s", path)
		}
	}
}

func TestBinaryCheckTokenIsRemovedOnRedirect(t *testing.T) {
	for _, crossOrigin := range []bool{false, true} {
		t.Run(fmt.Sprintf("cross-origin=%t", crossOrigin), func(t *testing.T) {
			u, f := newBinaryFixture(t)
			t.Setenv("GITHUB_TOKEN", "test-update-token")
			f.redirect = "/redirected"
			var received chan string
			if crossOrigin {
				received = make(chan string, 1)
				destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					received <- r.Header.Get("Authorization")
					fmt.Fprint(w, `{"tag_name":"v0.1.48"}`)
				}))
				defer destination.Close()
				f.redirect = destination.URL + "/redirected"
			}
			if _, err := u.Check(context.Background()); err != nil {
				t.Fatal(err)
			}
			if f.authorization["/latest"] != "Bearer test-update-token" {
				t.Fatal("initial API request was not authenticated")
			}
			authorization := f.authorization["/redirected"]
			if crossOrigin {
				authorization = <-received
			}
			if authorization != "" {
				t.Fatal("token leaked through redirect")
			}
		})
	}
}

func TestBinaryCheckWorksWithoutToken(t *testing.T) {
	u, f := newBinaryFixture(t)
	if _, err := u.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.authorization["/latest"] != "" {
		t.Fatal("anonymous API check unexpectedly carried authorization")
	}
}

func TestBinaryUpdateNeverDowngradesOrReinstalls(t *testing.T) {
	for _, version := range []string{"0.1.49", "0.1.50", "0.2.0", "0.1.100"} {
		t.Run(version, func(t *testing.T) {
			u, f := newBinaryFixture(t)
			u.version = version
			result, err := u.Update(context.Background())
			if err != nil || result.Available || result.Updated {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
			if strings.Join(f.requests, ",") != "/latest" {
				t.Fatalf("unexpected requests: %v", f.requests)
			}
			assertBinaryContent(t, u.targetPath, "old executable")
		})
	}
}

func TestBinaryUpdateCancellation(t *testing.T) {
	u, _ := newBinaryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := u.Update(ctx)
	if err == nil || result.Updated {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
	assertBinaryContent(t, u.targetPath, "old executable")
}

func TestBinaryUpdateRunningExecutable(t *testing.T) {
	const marker = "dddd-next updated executable probe\n"
	if mode := os.Getenv("DDDD_TEST_UPDATE_MODE"); mode != "" {
		if mode == "probe" {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(exe)
			if err != nil || !strings.HasSuffix(string(data), marker) {
				t.Fatal("replacement executable marker missing", err)
			}
			return
		}
		der, err := hex.DecodeString(os.Getenv("DDDD_TEST_UPDATE_CERT"))
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AddCert(cert)
		u := NewBinaryUpdater("0.1.48")
		u.releaseURL = os.Getenv("DDDD_TEST_UPDATE_URL")
		u.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots}
		result, err := u.Update(context.Background())
		if err != nil || !result.Updated {
			t.Fatalf("running executable update = %+v, %v", result, err)
		}
		return
	}
	u, f := newBinaryFixture(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(u.targetPath, original, 0755); err != nil {
		t.Fatal(err)
	}
	f.asset = "dddd-next_0.1.49_" + runtime.GOOS + "_" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		f.asset += ".exe"
	}
	f.payload = string(original) + marker
	f.size = len(f.payload)
	for _, mode := range []string{"update", "probe"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, u.targetPath, "-test.run=^TestBinaryUpdateRunningExecutable$", "-test.v")
		cmd.Env = append(os.Environ(), "DDDD_TEST_UPDATE_MODE="+mode, "DDDD_TEST_UPDATE_URL="+u.releaseURL, "DDDD_TEST_UPDATE_CERT="+f.certificate)
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("%s subprocess: %v\n%s", mode, err, output)
		}
		t.Logf("%s subprocess:\n%s", mode, output)
	}
}

func assertBinaryContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("binary at %s = %q, %v; want %q", path, got, err, want)
	}
}

package updater

import (
	"bytes"
	"context"
	"crypto"
	_ "crypto/sha256" // selfupdate 通过 crypto.Hash 计算 SHA-256。
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/minio/selfupdate"
)

const maxBinarySize = 512 << 20

// BinaryUpdater 从本项目的 GitHub Release 更新单文件程序。
// 模板更新仍由 Updater 负责，两者不会隐式触发对方。
type BinaryUpdater struct {
	version    string
	releaseURL string
	client     *http.Client
	targetPath string
	goos       string
	goarch     string
	progress   io.Writer
}

type BinaryRelease struct {
	Version   string
	Available bool
	Updated   bool

	assetName   string
	binaryURL   string
	checksumURL string
	size        int64
}

func NewBinaryUpdater(version string) *BinaryUpdater {
	return &BinaryUpdater{
		version:    version,
		releaseURL: "https://api.github.com/repos/galact-byte/dddd-next/releases/latest",
		goos:       runtime.GOOS,
		goarch:     runtime.GOARCH,
		progress:   os.Stderr,
		client: &http.Client{
			Timeout: 5 * time.Minute,
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				IdleConnTimeout:       90 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// 令牌仅授权初始 API 请求，不随重定向传播。
				req.Header.Del("Authorization")
				if req.URL.Scheme != "https" {
					return fmt.Errorf("update redirects must use HTTPS")
				}
				if len(via) >= 10 {
					return fmt.Errorf("too many update redirects")
				}
				return nil
			},
		},
	}
}

// Check 只读取发布元数据，不下载程序或修改本地文件。
func (u *BinaryUpdater) Check(ctx context.Context) (BinaryRelease, error) {
	var result BinaryRelease
	current, err := semver.NewVersion(u.version)
	if err != nil {
		return result, fmt.Errorf("invalid current version %q: %w", u.version, err)
	}
	body, err := u.get(ctx, u.releaseURL, 2<<20)
	if err != nil {
		return result, fmt.Errorf("check latest release: %w", err)
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return result, fmt.Errorf("decode latest release: %w", err)
	}
	latest, err := semver.NewVersion(release.Tag)
	if err != nil || release.Draft || release.Prerelease || latest.Prerelease() != "" {
		return result, fmt.Errorf("invalid stable release %q", release.Tag)
	}
	result.Version = latest.String()
	result.Available = latest.GreaterThan(current)
	if !result.Available {
		return result, nil
	}
	result.assetName = fmt.Sprintf("dddd-next_%s_%s_%s", latest.String(), u.goos, u.goarch)
	if u.goos == "windows" {
		result.assetName += ".exe"
	}
	for _, asset := range release.Assets {
		switch asset.Name {
		case result.assetName:
			if result.binaryURL != "" {
				return result, fmt.Errorf("duplicate release asset %s", asset.Name)
			}
			result.binaryURL, result.size = asset.URL, asset.Size
		case "checksums.txt":
			if result.checksumURL != "" {
				return result, fmt.Errorf("duplicate checksums.txt asset")
			}
			result.checksumURL = asset.URL
		}
	}
	if result.binaryURL == "" {
		return result, fmt.Errorf("release %s has no binary for %s/%s (%s)", release.Tag, u.goos, u.goarch, result.assetName)
	}
	if result.checksumURL == "" || result.size <= 0 || result.size > maxBinarySize {
		return result, fmt.Errorf("release %s has missing checksums.txt or invalid binary size", release.Tag)
	}
	return result, nil
}

func (u *BinaryUpdater) Update(ctx context.Context) (BinaryRelease, error) {
	result, err := u.Check(ctx)
	if err != nil || !result.Available {
		return result, err
	}
	target := u.targetPath
	if target == "" {
		target, err = os.Executable()
		if err != nil {
			return result, err
		}
	}
	// 跟随启动程序的符号链接，避免把链接本身替换为另一份程序。
	target, err = filepath.EvalSymlinks(target)
	if err != nil {
		return result, fmt.Errorf("resolve executable: %w", err)
	}
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() {
		return result, fmt.Errorf("executable is not a regular file: %s", target)
	}
	opts := selfupdate.Options{TargetPath: target, TargetMode: info.Mode().Perm(), Hash: crypto.SHA256}
	if err := opts.CheckPermissions(); err != nil {
		return result, fmt.Errorf("cannot update %s; check directory permissions: %w", target, err)
	}
	fmt.Fprintf(u.progress, "[updater] %s -> %s\n[updater] executable: %s\n", u.version, result.Version, target)
	checksums, err := u.get(ctx, result.checksumURL, 1<<20)
	if err != nil {
		return result, fmt.Errorf("download checksums: %w", err)
	}
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.TrimPrefix(fields[1], "*") != result.assetName {
			continue
		}
		if opts.Checksum != nil {
			return result, fmt.Errorf("duplicate checksum for %s", result.assetName)
		}
		opts.Checksum, err = hex.DecodeString(fields[0])
		if err != nil || len(opts.Checksum) != 32 {
			return result, fmt.Errorf("invalid SHA-256 checksum for %s", result.assetName)
		}
	}
	if opts.Checksum == nil {
		return result, fmt.Errorf("missing SHA-256 checksum for %s", result.assetName)
	}
	fmt.Fprintf(u.progress, "[updater] downloading %s (%.1f MiB)\n", result.assetName, float64(result.size)/(1<<20))
	bar := &downloadBar{w: u.progress, total: result.size, start: time.Now()}
	binary, err := u.fetch(ctx, result.binaryURL, result.size, bar)
	bar.finish()
	if err != nil {
		return result, fmt.Errorf("download binary: %w", err)
	}
	if int64(len(binary)) != result.size {
		return result, fmt.Errorf("binary size mismatch: expected %d, got %d", result.size, len(binary))
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := selfupdate.Apply(bytes.NewReader(binary), opts); err != nil {
		if rollbackErr := selfupdate.RollbackError(err); rollbackErr != nil {
			return result, fmt.Errorf("update failed: %v; rollback failed: %v; recover %s manually", err, rollbackErr, target)
		}
		return result, fmt.Errorf("update failed (original executable retained): %w", err)
	}
	result.Updated = true
	return result, nil
}

func (u *BinaryUpdater) get(ctx context.Context, address string, limit int64) ([]byte, error) {
	return u.fetch(ctx, address, limit, nil)
}

// fetch reads at most limit bytes; received bytes are also written to
// progress when it is non-nil.
func (u *BinaryUpdater) fetch(ctx context.Context, address string, limit int64, progress io.Writer) ([]byte, error) {
	parsed, err := url.Parse(address)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("invalid HTTPS update URL")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "dddd-next/"+u.version)
	if address == u.releaseURL {
		if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, parsed.Host)
	}
	var body io.Reader = io.LimitReader(resp.Body, limit+1)
	if progress != nil {
		body = io.TeeReader(body, progress)
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("download exceeds expected size limit (%d bytes)", limit)
	}
	return data, nil
}

// downloadBar renders a single self-overwriting progress line such as
//
//	[==============>               ]  48%   12.3/25.6 MiB   3.1 MiB/s
type downloadBar struct {
	w           io.Writer
	total, done int64
	start, last time.Time
	rendered    bool
}

const downloadBarWidth = 30

func (b *downloadBar) Write(p []byte) (int, error) {
	b.done += int64(len(p))
	if now := time.Now(); b.done >= b.total || now.Sub(b.last) >= 100*time.Millisecond {
		b.last = now
		b.render(now)
	}
	return len(p), nil
}

func (b *downloadBar) render(now time.Time) {
	fraction := 0.0
	if b.total > 0 {
		fraction = min(float64(b.done)/float64(b.total), 1)
	}
	filled := int(fraction * downloadBarWidth)
	bar := strings.Repeat("=", filled)
	if filled < downloadBarWidth {
		bar += ">" + strings.Repeat(" ", downloadBarWidth-filled-1)
	}
	// The first frames would divide by a near-zero duration and flash an
	// absurd rate, so the speed column waits for half a second of data; the
	// final frame always shows the real average.
	speed := "  --.-"
	if elapsed := now.Sub(b.start).Seconds(); elapsed >= 0.5 || (b.done >= b.total && elapsed > 0) {
		speed = fmt.Sprintf("%6.1f", float64(b.done)/elapsed/(1<<20))
	}
	// Trailing spaces clear leftovers when the speed column shrinks.
	fmt.Fprintf(b.w, "\r  [%s] %3.0f%%  %5.1f/%.1f MiB  %s MiB/s  ",
		bar, fraction*100, float64(b.done)/(1<<20), float64(b.total)/(1<<20), speed)
	b.rendered = true
}

// finish ends the progress line so later messages start on a fresh line.
func (b *downloadBar) finish() {
	if b.rendered {
		fmt.Fprintln(b.w)
	}
}

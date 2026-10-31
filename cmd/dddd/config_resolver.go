package main

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	builtinconfigs "dddd-next/configs"
)

const builtinConfigVersionFile = ".builtin-version"

func resolveConfigDir() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	return resolveConfigDirWith(exePath, builtinconfigs.BundleZip, appVersion)
}

func resolveConfigDirWith(exePath string, builtinZip []byte, version string) (string, error) {
	if exePath == "" {
		return "", errors.New("cannot resolve executable path")
	}
	dest := filepath.Join(filepath.Dir(exePath), "configs")
	if dirExists(dest) {
		return dest, nil
	}
	if err := materializeBuiltinConfigs(dest, builtinZip, version); err != nil {
		return "", fmt.Errorf("prepare configs at %s (place the program in a writable directory): %w", dest, err)
	}
	return dest, nil
}

func materializeBuiltinConfigs(dest string, bundle []byte, version string) error {
	if len(bundle) == 0 {
		return errors.New("built-in config bundle is empty")
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}

	markerPath := filepath.Join(dest, builtinConfigVersionFile)
	currentVersion := ""
	if data, err := os.ReadFile(markerPath); err == nil {
		currentVersion = strings.TrimSpace(string(data))
	}
	refresh := currentVersion != version

	reader, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		return fmt.Errorf("open built-in config bundle: %w", err)
	}

	seenFiles := 0
	for _, entry := range reader.File {
		target, err := safeConfigBundleTarget(dest, entry.Name)
		if err != nil {
			return err
		}
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		seenFiles++

		if !refresh && fileExists(target) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		src, err := entry.Open()
		if err != nil {
			return err
		}
		dst, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fileMode(entry))
		if err != nil {
			_ = src.Close()
			return err
		}
		_, copyErr := io.Copy(dst, src)
		closeErr := dst.Close()
		srcErr := src.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if srcErr != nil {
			return srcErr
		}
	}
	if seenFiles == 0 {
		return errors.New("built-in config bundle contains no files")
	}
	return os.WriteFile(markerPath, []byte(version+"\n"), 0o644)
}

func safeConfigBundleTarget(dest, name string) (string, error) {
	cleanName := filepath.Clean(filepath.FromSlash(name))
	if cleanName == "." || cleanName == ".." || filepath.IsAbs(cleanName) || strings.HasPrefix(cleanName, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe path in built-in config bundle: %s", name)
	}
	target := filepath.Join(dest, cleanName)
	rel, err := filepath.Rel(dest, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe path in built-in config bundle: %s", name)
	}
	return target, nil
}

func fileMode(entry *zip.File) os.FileMode {
	mode := entry.Mode().Perm()
	if mode == 0 {
		return 0o644
	}
	return mode
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

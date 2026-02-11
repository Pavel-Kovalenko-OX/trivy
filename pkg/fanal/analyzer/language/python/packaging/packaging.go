package packaging

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/packaging"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePythonPkg, newPackagingAnalyzer)
}

const version = 3

func newPackagingAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &packagingAnalyzer{
		logger:                           log.WithPrefix("python"),
		pkgParser:                        packaging.NewParser(),
		licenseClassifierConfidenceLevel: opt.LicenseScannerOption.ClassifierConfidenceLevel,
		listAllLangPkgs:                  opt.ListAllLangPkgs,
	}, nil
}

var (
	eggFiles = []string{
		// .egg format
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		// ".egg" is zip format. We check it in `eggAnalyzer`.
		"EGG-INFO/PKG-INFO",

		// .egg-info format: .egg-info can be a file or directory
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		".egg-info",
		".egg-info/PKG-INFO",
		// https://github.com/aquasecurity/trivy/issues/9171
		".egg-info/METADATA",
	}
)

type packagingAnalyzer struct {
	logger                           *log.Logger
	pkgParser                        language.Parser
	licenseClassifierConfidenceLevel float64
	listAllLangPkgs                  bool
}

// PostAnalyze analyzes egg and wheel files.
func (a packagingAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {

	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == "METADATA" || isEggFile(path) || input.FilePatterns.Match(path)
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		rsa, ok := r.(xio.ReadSeekerAt)
		if !ok {
			return xerrors.New("invalid reader")
		}

		app, err := a.parse(ctx, filePath, rsa, input.Options.FileChecksum)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		opener := func(licPath string) (io.ReadCloser, error) {
			// Note that fs.FS is always slashed regardless of the platform,
			// and path.Join should be used rather than filepath.Join.
			f, err := input.FS.Open(path.Join(path.Dir(filePath), licPath))
			if errors.Is(err, fs.ErrNotExist) {
				return nil, nil
			} else if err != nil {
				return nil, xerrors.Errorf("file open error: %w", err)
			}
			return f, nil
		}

		if err = fillAdditionalData(opener, app, a.licenseClassifierConfidenceLevel); err != nil {
			a.logger.Warn("Unable to collect additional info", log.Err(err))
		}

		// Read RECORD file to get installed files for .dist-info packages (only if flag is enabled)
		if a.listAllLangPkgs && strings.Contains(filePath, ".dist-info/METADATA") {
			// RECORD paths are relative to the parent of .dist-info directory (site-packages)
			// e.g., if METADATA is at "app/venv/lib/python3.10/site-packages/pkg-1.0.dist-info/METADATA"
			// then RECORD paths should be prefixed with "app/venv/lib/python3.10/site-packages/"
			distInfoDir := path.Dir(filePath)        // app/venv/.../pkg-1.0.dist-info
			sitePackagesDir := path.Dir(distInfoDir) // app/venv/.../site-packages
			if installedFiles, err := a.parseRecordFile(input.FS, distInfoDir, sitePackagesDir); err != nil {
				a.logger.Debug("Unable to parse RECORD file", log.FilePath(filePath), log.Err(err))
			} else if len(installedFiles) > 0 && len(app.Packages) > 0 {
				app.Packages[0].InstalledFiles = installedFiles
			}
		}

		apps = append(apps, *app)
		return nil
	})

	if err != nil {
		return nil, xerrors.Errorf("python package walk error: %w", err)
	}
	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

type fileOpener func(filePath string) (io.ReadCloser, error)

func fillAdditionalData(opener fileOpener, app *types.Application, licenseClassifierConfidenceLevel float64) error {
	for i, pkg := range app.Packages {
		var licenses []string
		for _, lic := range pkg.Licenses {
			// Parser adds `file://` prefix to filepath from `License-File` field
			// We need to read this file to find licenses
			// Otherwise, this is the name of the license
			if !strings.HasPrefix(lic, licensing.LicenseFilePrefix) {
				licenses = append(licenses, lic)
				continue
			}
			licensePath := path.Base(strings.TrimPrefix(lic, licensing.LicenseFilePrefix))

			foundLicenses, err := classifyLicenses(opener, licensePath, licenseClassifierConfidenceLevel)
			if err != nil {
				return xerrors.Errorf("unable to classify licenses: %w", err)
			}
			licenses = append(licenses, foundLicenses...)
		}
		app.Packages[i].Licenses = licenses
	}

	return nil
}

func classifyLicenses(opener fileOpener, licPath string, licenseClassifierConfidenceLevel float64) ([]string, error) {
	f, err := opener(licPath)
	if err != nil {
		return nil, xerrors.Errorf("unable to open license file: %w", err)
	} else if f == nil { // File doesn't exist
		return nil, nil
	}
	defer f.Close()

	l, err := licensing.Classify("", f, licenseClassifierConfidenceLevel)
	if err != nil {
		return nil, xerrors.Errorf("license classify error: %w", err)
	} else if l == nil { // No licenses found
		return nil, nil
	}

	// License found
	return lo.Map(l.Findings, func(finding types.LicenseFinding, _ int) string {
		return finding.Name
	}), nil
}

func (a packagingAnalyzer) parse(ctx context.Context, filePath string, r xio.ReadSeekerAt, checksum bool) (*types.Application, error) {
	return language.ParsePackage(ctx, types.PythonPkg, filePath, r, a.pkgParser, checksum)
}

// parseRecordFile reads the RECORD file from a .dist-info directory and extracts file paths.
// The RECORD file is a CSV with format: path,hash,size
// Paths in RECORD are relative to sitePackagesDir (parent of distInfoDir).
// We convert them to absolute paths to match the format of OS packages InstalledFiles.
func (a packagingAnalyzer) parseRecordFile(fsys fs.FS, distInfoDir, sitePackagesDir string) ([]string, error) {
	recordPath := path.Join(distInfoDir, "RECORD")
	f, err := fsys.Open(recordPath)
	if errors.Is(err, fs.ErrNotExist) {
		// RECORD file is optional
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("failed to open RECORD file: %w", err)
	}
	defer f.Close()

	var installedFiles []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		// RECORD format is CSV: path,hash,size
		// We only need the first field (path)
		if idx := strings.Index(line, ","); idx > 0 {
			relativePath := line[:idx]
			if relativePath != "" {
				// Convert relative path to absolute Unix path by adding leading slash
				// and joining with site-packages directory
				absolutePath := "/" + path.Join(sitePackagesDir, relativePath)
				installedFiles = append(installedFiles, absolutePath)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("failed to read RECORD file: %w", err)
	}

	return installedFiles, nil
}

func (a packagingAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.Contains(filePath, ".dist-info") || isEggFile(filePath)
}

func isEggFile(filePath string) bool {
	return lo.SomeBy(eggFiles, func(fileName string) bool {
		return strings.HasSuffix(filePath, fileName)
	})
}

func (a packagingAnalyzer) Type() analyzer.Type {
	return analyzer.TypePythonPkg
}

func (a packagingAnalyzer) Version() int {
	return version
}

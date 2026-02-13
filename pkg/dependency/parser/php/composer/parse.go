package composer

import (
	"context"
	"path"
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type LockFile struct {
	Packages []packageInfo `json:"packages"`
}
type packageInfo struct {
	Name        string            `json:"name"`
	Version     string            `json:"version"`
	Require     map[string]string `json:"require"`
	License     any               `json:"license"`
	InstallPath string            `json:"install-path"` // Relative path to the package installation directory
	xjson.Location
}

type Parser struct {
	logger          *log.Logger
	listAllLangPkgs bool
	filePath        string // Path to the installed.json file
}

func NewParser(listAllLangPkgs bool) *Parser {
	return &Parser{
		logger:          log.WithPrefix("composer"),
		listAllLangPkgs: listAllLangPkgs,
	}
}

// SetFilePath sets the path to the installed.json file for computing absolute paths
func (p *Parser) SetFilePath(filePath string) {
	p.filePath = filePath
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile LockFile
	if err := xjson.UnmarshalRead(r, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	pkgs := make(map[string]ftypes.Package)
	foundDeps := make(map[string][]string)
	for _, lpkg := range lockFile.Packages {
		pkg := ftypes.Package{
			ID:           dependency.ID(ftypes.Composer, lpkg.Name, lpkg.Version),
			Name:         lpkg.Name,
			Version:      lpkg.Version,
			Relationship: ftypes.RelationshipUnknown, // composer.lock file doesn't have info about direct/indirect dependencies
			Licenses:     licenses(lpkg.License),
			Locations:    []ftypes.Location{ftypes.Location(lpkg.Location)},
		}

		// Extract install-path if listAllLangPkgs is enabled
		if p.listAllLangPkgs && lpkg.InstallPath != "" {
			pkg.InstalledFiles = []string{p.normalizeInstallPath(lpkg.InstallPath)}
		}

		pkgs[pkg.Name] = pkg

		var dependsOn []string
		for depName := range lpkg.Require {
			// Require field includes required php version, skip this
			// Also skip PHP extensions
			if depName == "php" || strings.HasPrefix(depName, "ext") {
				continue
			}
			dependsOn = append(dependsOn, depName) // field uses range of versions, so later we will fill in the versions from the packages
		}
		if len(dependsOn) > 0 {
			foundDeps[pkg.ID] = dependsOn
		}
	}

	// fill deps versions
	var deps ftypes.Dependencies
	for pkgID, depsOn := range foundDeps {
		var dependsOn []string
		for _, depName := range depsOn {
			if pkg, ok := pkgs[depName]; ok {
				dependsOn = append(dependsOn, pkg.ID)
				continue
			}
			p.logger.Debug("Unable to find version", log.String("name", depName))
		}
		sort.Strings(dependsOn)
		deps = append(deps, ftypes.Dependency{
			ID:        pkgID,
			DependsOn: dependsOn,
		})
	}

	pkgSlice := lo.Values(pkgs)
	sort.Sort(ftypes.Packages(pkgSlice))
	sort.Sort(deps)

	return pkgSlice, deps, nil
}

// normalizeInstallPath converts relative install-path to absolute path.
// install-path is relative to the installed.json file.
// Example: "../pear/log" from "/app/vendor/composer/installed.json" becomes "/app/vendor/pear/log"
func (p *Parser) normalizeInstallPath(installPath string) string {
	if p.filePath == "" {
		// If filePath is not set, return the install-path as-is with leading slash
		return "/" + installPath
	}

	// Get the directory containing installed.json
	installedDir := path.Dir(p.filePath)

	// Join and clean the path to resolve ".." components
	// path.Clean removes redundant separators and resolves ".." and "."
	absolutePath := path.Clean("/" + path.Join(installedDir, installPath))

	return absolutePath
}

// licenses returns slice of licenses from string, string with separators (`or`, `and`, etc.) or string array
// cf. https://getcomposer.org/doc/04-schema.md#license
func licenses(val any) []string {
	switch v := val.(type) {
	case string:
		if v != "" {
			return licensing.SplitLicenses(v)
		}
	case []any:
		var lics []string
		for _, l := range v {
			if lic, ok := l.(string); ok {
				lics = append(lics, lic)
			}
		}
		return lics
	}
	return nil
}

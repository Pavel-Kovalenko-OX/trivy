package composer

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/php/composer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&composerVendorAnalyzer{})
}

const (
	composerInstalledAnalyzerVersion = 2
)

// Ensure composerVendorAnalyzer implements analyzer.Initializer
var _ analyzer.Initializer = (*composerVendorAnalyzer)(nil)

// composerVendorAnalyzer analyzes 'installed.json'
type composerVendorAnalyzer struct {
	listAllLangPkgs bool
}

func (a *composerVendorAnalyzer) Init(opt analyzer.AnalyzerOptions) error {
	a.listAllLangPkgs = opt.ListAllLangPkgs
	return nil
}

func (a composerVendorAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	parser := composer.NewParser(a.listAllLangPkgs)
	parser.SetFilePath(input.FilePath)
	return language.Analyze(ctx, types.ComposerVendor, input.FilePath, input.Content, parser)
}

func (a composerVendorAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.ComposerInstalledJson
}

func (a composerVendorAnalyzer) Type() analyzer.Type {
	return analyzer.TypeComposerVendor
}

func (a composerVendorAnalyzer) Version() int {
	return composerInstalledAnalyzerVersion
}

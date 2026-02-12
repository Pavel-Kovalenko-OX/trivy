package deps

import (
	"context"
	"os"
	"strings"

	"golang.org/x/xerrors"

	core "github.com/aquasecurity/trivy/pkg/dependency/parser/dotnet/core_deps"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&depsLibraryAnalyzer{})
}

const (
	version       = 2
	depsExtension = ".deps.json"
)

// Ensure depsLibraryAnalyzer implements analyzer.Initializer
var _ analyzer.Initializer = (*depsLibraryAnalyzer)(nil)

type depsLibraryAnalyzer struct {
	listAllLangPkgs bool
}

func (a *depsLibraryAnalyzer) Init(opt analyzer.AnalyzerOptions) error {
	a.listAllLangPkgs = opt.ListAllLangPkgs
	return nil
}

func (a depsLibraryAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	parser := core.NewParser(a.listAllLangPkgs)
	parser.SetFilePath(input.FilePath)
	res, err := language.Analyze(ctx, types.DotNetCore, input.FilePath, input.Content, parser)
	if err != nil {
		return nil, xerrors.Errorf(".Net Core dependencies analysis error: %w", err)
	}

	return res, nil
}

func (a depsLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.HasSuffix(filePath, depsExtension)
}

func (a depsLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeDotNetCore
}

func (a depsLibraryAnalyzer) Version() int {
	return version
}

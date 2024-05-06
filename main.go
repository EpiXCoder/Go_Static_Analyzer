package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type finding struct {
	File    string
	Line    int
	Message string
}

func main() {
	// Add a flag to control the number of repositories to clone
	org := flag.String("org", "", "GitHub organization or username")
	token := flag.String("token", "", "GitHub personal access token")
	all := flag.Bool("all", false, "Clone all repositories instead of just the latest 10")
	flag.Parse()

	if *org == "" || *token == "" {
		fmt.Println("Usage: static-analyzer -org=<github-org-or-user> -token=<github-token> [-all]")
		return
	}

	clonedRepos := cloneRepositories(*org, *token, *all)
	if len(clonedRepos) == 0 {
		fmt.Println("No repositories cloned.")
		return
	}

	findings := make(chan finding, len(clonedRepos))
	var wg sync.WaitGroup

	for _, repo := range clonedRepos {
		wg.Add(1)
		go func(repo string) {
			defer wg.Done()
			analyzeRepo(repo, findings)
		}(repo)
	}

	go func() {
		wg.Wait()
		close(findings)
	}()

	for f := range findings {
		fmt.Printf("Found issue in %s at line %d: %s\n", f.File, f.Line, f.Message)
	}
}

func analyzeRepo(repo string, findings chan finding) {
	repoName := filepath.Base(repo)
	if ignoredRepos[strings.ToLower(repoName)] {
		fmt.Println("Ignoring repository during analysis:", repoName)
		return
	}

	err := filepath.Walk(repo, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && isGoFile(info.Name()) {
			analyzeFile(path, findings, &sync.WaitGroup{})
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error analyzing repository:", err)
	}
}

func analyzeFile(path string, findings chan finding, wg *sync.WaitGroup) {
	wg.Add(1)
	defer wg.Done()

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, path, nil, parser.AllErrors)
	if err != nil {
		findings <- finding{File: path, Line: 0, Message: "Error parsing file"}
		return
	}

	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.BasicLit:
			checkHardcodedCredentials(x, path, fset, findings)
		case *ast.CallExpr:
			checkInsecureHTTP(x, path, fset, findings)
			checkCommandInjection(x, path, fset, findings)
		}
		return true
	})
}

func checkHardcodedCredentials(n *ast.BasicLit, path string, fset *token.FileSet, findings chan finding) {
	if n.Kind == token.STRING {
		// Regex pattern to detect potential credentials
		pattern := `(?i)(password|secret|token|apikey|auth)`
		matched, _ := regexp.MatchString(pattern, n.Value)
		if matched {
			pos := fset.Position(n.Pos())
			findings <- finding{File: path, Line: pos.Line, Message: "Potential hardcoded credentials"}
		}
	}
}

func checkInsecureHTTP(n *ast.CallExpr, path string, fset *token.FileSet, findings chan finding) {
	if funcIdent, ok := n.Fun.(*ast.SelectorExpr); ok {
		if strings.HasPrefix(funcIdent.Sel.Name, "Get") {
			for _, arg := range n.Args {
				if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING && strings.HasPrefix(lit.Value, `"http://`) {
					pos := fset.Position(lit.Pos())
					findings <- finding{File: path, Line: pos.Line, Message: "Insecure HTTP URL detected"}
				}
			}
		}
	}
}

func checkCommandInjection(n *ast.CallExpr, path string, fset *token.FileSet, findings chan finding) {
	if funcIdent, ok := n.Fun.(*ast.SelectorExpr); ok && funcIdent.Sel.Name == "Command" {
		pos := fset.Position(n.Pos())
		findings <- finding{File: path, Line: pos.Line, Message: "Potential command injection detected"}
	}
}

func isGoFile(name string) bool {
	return len(name) > 3 && name[len(name)-3:] == ".go"
}




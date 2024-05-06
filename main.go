package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type finding struct {
	File    string
	Line    int
	Message string
}

const (
    green  = "\033[32m"
    red    = "\033[31m"
    reset  = "\033[0m"
)

func main() {
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

	foundIssues := false
	for f := range findings {
		foundIssues = true
		fmt.Printf("Found issue in %s at line %d: %s\n", f.File, f.Line, f.Message)
		logFindingToFile(f)
	}

	if !foundIssues {
        fmt.Println(green, "No vulnerabilities identified", reset)
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
	if n == nil || n.Fun == nil {
		return
	}

	if funcIdent, ok := n.Fun.(*ast.SelectorExpr); ok && funcIdent.Sel.Name == "Command" {
		pos := fset.Position(n.Pos())
		findings <- finding{File: path, Line: pos.Line, Message: "Potential command injection detected"}
	}
}

func logFindingToFile(finding finding) {

	fileName := "analysis_log.txt"
	logFile, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println("Could not open log file:", err)
		return
	}
	defer logFile.Close()

	logger := log.New(logFile, "", log.LstdFlags)
	logMsg := fmt.Sprintf("Date: %s, File: %s, Line: %d, Message: %s",
		time.Now().Format("2006-01-02 15:04:05"),
		finding.File,
		finding.Line,
		finding.Message)

	logger.Println(logMsg)
}

func isGoFile(name string) bool {
	return len(name) > 3 && name[len(name)-3:] == ".go"
}

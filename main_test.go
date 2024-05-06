package main

import (
    "go/token"
    "go/ast"
    "testing"
)

func TestCheckHardcodedCredentials(t *testing.T) {
    testCases := []struct {
        name     string
        input    string
        expected bool
    }{
        {"Hardcoded Password", "\"password123\"", true},
        {"API Key", "\"APIKEY12345\"", true},
        {"Random String", "\"Hello, World!\"", false},
        {"Empty String", "\"\"", false},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            n := &ast.BasicLit{Kind: token.STRING, Value: tc.input}
            findings := make(chan finding, 1)
            checkHardcodedCredentials(n, "test.go", token.NewFileSet(), findings)
            close(findings)

            if tc.expected {
                if len(findings) == 0 {
                    t.Errorf("Expected finding but got none")
                }
            } else {
                if len(findings) != 0 {
                    t.Errorf("Expected no findings but got one")
                }
            }
        })
    }
}

func TestCheckInsecureHTTP(t *testing.T) {
    testCases := []struct {
        name     string
        input    string
        expected bool
    }{
        {"HTTP URL", "\"http://example.com\"", true},
        {"HTTPS URL", "\"https://example.com\"", false},
        {"Non-URL String", "\"Not a URL\"", false},
        {"Empty String", "\"\"", false},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            arg := &ast.BasicLit{Kind: token.STRING, Value: tc.input}
            n := &ast.CallExpr{
                Fun: &ast.SelectorExpr{
                    X:   ast.NewIdent("http"),
                    Sel: ast.NewIdent("Get"),
                },
                Args: []ast.Expr{arg},
            }
            findings := make(chan finding, 1)
            checkInsecureHTTP(n, "test.go", token.NewFileSet(), findings)
            close(findings)

            if tc.expected {
                if len(findings) == 0 {
                    t.Errorf("Expected finding but got none")
                }
            } else {
                if len(findings) != 0 {
                    t.Errorf("Expected no findings but got one")
                }
            }
        })
    }
}

func TestCheckCommandInjection(t *testing.T) {
    testCases := []struct {
        name     string
        function string
        expected bool
    }{
        {"Exec Command", "Command", true},
        {"Exec", "Exec", false},
        {"Not a Command", "NotACommand", false},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            n := &ast.CallExpr{
                Fun: &ast.SelectorExpr{
                    X:   ast.NewIdent("exec"), 
                    Sel: ast.NewIdent(tc.function),
                },
            }
            findings := make(chan finding, 1)
            checkCommandInjection(n, "test.go", token.NewFileSet(), findings)
            close(findings)

            if tc.expected {
                if len(findings) == 0 {
                    t.Errorf("Expected finding but got none")
                }
            } else {
                if len(findings) != 0 {
                    t.Errorf("Expected no findings but got one")
                }
            }
        })
    }
}


func TestIsGoFile(t *testing.T) {
    testCases := []struct {
        name     string
        input    string
        expected bool
    }{
        {"Go File", "main.go", true},
        {"Text File", "main.txt", false},
        {"Empty String", "", false},
        {"No Extension", "file", false},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            result := isGoFile(tc.input)
            if result != tc.expected {
                t.Errorf("Expected %v, got %v", tc.expected, result)
            }
        })
    }
}

func BenchmarkCheckHardcodedCredentials(b *testing.B) {
    n := &ast.BasicLit{Kind: token.STRING, Value: "\"password123\""}
    for i := 0; i < b.N; i++ {
        findings := make(chan finding, 1)
        checkHardcodedCredentials(n, "test.go", token.NewFileSet(), findings)
        close(findings)
    }
}

func BenchmarkCheckInsecureHTTP(b *testing.B) {
    arg := &ast.BasicLit{Kind: token.STRING, Value: "\"http://example.com\""}
    n := &ast.CallExpr{
        Fun: &ast.SelectorExpr{
            X:   ast.NewIdent("http"),
            Sel: ast.NewIdent("Get"),
        },
        Args: []ast.Expr{arg},
    }
    for i := 0; i < b.N; i++ {
        findings := make(chan finding, 1)
        checkInsecureHTTP(n, "test.go", token.NewFileSet(), findings)
        close(findings)
    }
}

func BenchmarkCheckCommandInjection(b *testing.B) {
    for i := 0; i < b.N; i++ {
        n := &ast.CallExpr{
            Fun: &ast.SelectorExpr{
                X:   ast.NewIdent("exec"),
                Sel: ast.NewIdent("Command"), 
            },
        }
        findings := make(chan finding, 1)
        checkCommandInjection(n, "test.go", token.NewFileSet(), findings)
        close(findings)
    }
}



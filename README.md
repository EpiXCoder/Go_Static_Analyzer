# Static Analyzer

[![Go Report Card](https://goreportcard.com/badge/github.com/EpiXCoder/Go_Static_Analyzer)](https://goreportcard.com/report/github.com/EpiXCoder/Go_Static_Analyzer)


**Static Analyzer** is a command-line tool that scans Go code repositories for common security vulnerabilities. It helps developers identify insecure coding patterns before they reach production, ensuring better security for Go applications.

## Features
- **Repository Cloning:** Automatically fetches and clones repositories from a specified GitHub user or organization, with the option to clone either the latest 10 repositories or all repositories.
- **Code Analysis:** Parses Go files to inspect their syntax trees for insecure patterns.
- **Pattern Detection:** Flags insecure code, including:
  - **Hardcoded Credentials:** Detects suspicious string literals that may contain passwords, secrets, or API keys.
  - **Insecure HTTP URLs:** Identifies unsafe HTTP URLs used in network requests.
  - **Command Injection:** Flags usage of functions that may allow shell command injection.

## How to Use
1. **Build the Analyzer:** Compile the project to produce the binary:
    ```
    go build -o static-analyzer
    ```
2. **Get a GitHub Token**: Create a personal access token from GitHub.
    >Make sure it's valid and has the necessary permissions, like `repo` scope for private repositories.
    > Create a new token following these steps:
    > 1. Go to your GitHub account settings.
    > 2. Navigate to "Developer Settings" → "Personal Access Tokens".
    > 3. Generate a new token with the required scopes.

3. **Run the Analyzer**: Execute the analyzer with the GitHub username and token:
    ```
    ./static-analyzer -org=<github-username> -token=<github-token> [-all]
    ```
    Replace `<github-username>` with the GitHub username to analyze and `<github-token>` with your access token. The `-all` flag is optional and will clone all repositories if included. Otherwise, the analyzer will scan 10 most recently updated repos.

    **Examples**

    To scan all repos:
    ```
    ./static-analyzer -org=my-github-org -token=ghp_xxxxxxx -all
    ```

    To scan 10 most recently updated repos:
    ```
    ./static-analyzer -org=my-github-org -token=ghp_xxxxxxx
    ```

4. **View the Report**: The analyzer will output the findings to the console and log them to a file, listing insecure patterns found in the repositories.

## Example Output
```
Found issue in repo1/main.go at line 10: Potential hardcoded credentials
Found issue in repo2/server.go at line 24: Insecure HTTP URL detected
Found issue in repo3/utils.go at line 45: Potential command injection detected
```

## Sample Compromised Program
You can clone this compromised repo to test the program: https://github.com/EpiXCoder/Compromised_Repo

## Dependencies
```
go get github.com/go-git/go-git/v5
go get github.com/google/go-github/v41/github
go get golang.org/x/oauth2
```

## Notes
- The static analyzer is currently set up to clone and analyze all repositories or just the most recent 10.
- The cloned repositories are saved in a timestamped folder to keep them organized.

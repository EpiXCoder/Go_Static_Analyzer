package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/google/go-github/v41/github"
	"golang.org/x/oauth2"
)

// List of repositories to ignore (add names in lowercase)
var ignoredRepos = map[string]bool{
	"go_static_analyzer": true,
	// "repo-to-ignore-2": true,
}

func cloneRepositories(user string, token string, all bool) []string {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	// Create a timestamped directory
	dirName := fmt.Sprintf("%s_repos_%s", user, time.Now().Format("2006-01-02_15-04-05"))
	if err := os.MkdirAll(dirName, os.ModePerm); err != nil {
		fmt.Println("Error creating directory:", err)
		return nil
	}

	clonedRepos := make([]string, 0)
	var wg sync.WaitGroup
	mu := &sync.Mutex{}

	opt := &github.RepositoryListOptions{
		Sort:      "pushed",
		Direction: "desc",
	}

	if all {
		opt.PerPage = 100 // Retrieve up to 100 repositories per page
	} else {
		opt.PerPage = 10 // Retrieve only 10 repositories
	}

	page := 1
	for {
		opt.Page = page
		repos, _, err := client.Repositories.List(ctx, user, opt)
		if err != nil {
			fmt.Println("Error fetching repositories:", err)
			break
		}

		if len(repos) == 0 {
			break
		}

		for _, repo := range repos {
			repoName := repo.GetName()
			if ignoredRepos[strings.ToLower(repoName)] {
				fmt.Println("Ignoring repository:", repoName)
				continue
			}

			wg.Add(1)
			go func(repo *github.Repository) {
				defer wg.Done()
				repoPath := filepath.Join(dirName, repo.GetName())
				fmt.Println("Cloning repository:", repo.GetName())

				_, err := git.PlainClone(repoPath, false, &git.CloneOptions{
					URL: repo.GetCloneURL(),
				})

				if err != nil {
					fmt.Println("Error cloning repository:", err)
					return
				}

				mu.Lock()
				clonedRepos = append(clonedRepos, repoPath)
				mu.Unlock()
			}(repo)
		}

		page++
		if !all {
			break
		}
	}

	wg.Wait()
	return clonedRepos
}

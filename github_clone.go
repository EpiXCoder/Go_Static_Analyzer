package main

import (
    "context"
    "fmt"

    "github.com/go-git/go-git/v5"
    "github.com/google/go-github/v41/github"
    "golang.org/x/oauth2"
)

func cloneRepositories(user string, token string) []string {
    ctx := context.Background()
    ts := oauth2.StaticTokenSource(
        &oauth2.Token{AccessToken: token},
    )
    tc := oauth2.NewClient(ctx, ts)
    client := github.NewClient(tc)

    clonedRepos := make([]string, 0)
    opt := &github.RepositoryListOptions{
        Sort:        "pushed",
        Direction:   "desc", // Descending order (latest pushed first)
        ListOptions: github.ListOptions{PerPage: 10}, // Retrieve only the latest 10 repositories
    }

    repos, _, err := client.Repositories.List(ctx, user, opt)
    if err != nil {
        fmt.Println("Error fetching repositories:", err)
        return nil
    }

    for _, repo := range repos {
        repoName := repo.GetName()
        fmt.Println("Cloning repository:", repoName)

        _, err := git.PlainClone(repoName, false, &git.CloneOptions{
            URL: repo.GetCloneURL(),
        })

        if err != nil {
            fmt.Println("Error cloning repository:", err)
            continue
        }

        clonedRepos = append(clonedRepos, repoName)
    }

    return clonedRepos
}

package main

import (
	"context"
	"fmt"

	"github.com/buptczq/WinCryptSSHAgent/app"
	"golang.org/x/crypto/ssh/agent"
)

func startPageant(ag agent.Agent) {
	server := &Server{ag}
	p := &app.Pageant{}
	ctx, _ := context.WithCancel(context.Background())
	err := p.Run(ctx, server.SSHAgentHandler)
	if err != nil {
		panic(err)
	}
}

func main() {
	ag, err := NewSSHAgent()
	if err != nil {
		fmt.Println(err)
	}
	defer ag.Close()
	fmt.Println("starting pageant")
	startPageant(ag)
}

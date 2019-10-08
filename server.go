package main

import (
	"io"

	"golang.org/x/crypto/ssh/agent"
)

type Server struct {
	Agent agent.Agent
}

func (s *Server) SSHAgentHandler(conn io.ReadWriteCloser) {
	defer conn.Close()
	if s.Agent == nil {
		return
	}
	agent.ServeAgent(s.Agent, conn)
}

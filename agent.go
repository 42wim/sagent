package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"log"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type SSHAgent struct {
	mu   sync.Mutex
	keys []*sshKey
}

type sshKey struct {
	signer  ssh.Signer
	comment string
	pk      interface{}
}

func NewSSHAgent() (*SSHAgent, error) {
	s := &SSHAgent{}
	return s, nil
}

func (s *SSHAgent) Close() (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return nil
}

func (s *SSHAgent) List() (keys []*agent.Key, err error) {
	log.Println("List()")
	s.mu.Lock()
	defer s.mu.Unlock()

	var ids []*agent.Key
	for _, k := range s.keys {
		pub := k.signer.PublicKey()
		ids = append(ids, &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: k.comment})
	}
	return ids, nil
}

func (s *SSHAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	log.Println("Sign()")
	return s.SignWithFlags(key, data, 0)
}

func (s *SSHAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	wanted := key.Marshal()
	for _, k := range s.keys {
		if bytes.Equal(k.signer.PublicKey().Marshal(), wanted) {
			log.Println("Found a matching key", k.comment, "for", key)
		}
		sig, err := k.signer.Sign(rand.Reader, data)
		if err != nil {
			return sig, err
		}
		return sig, err
	}
	return nil, errors.New("not found")
}

func (s *SSHAgent) Add(key agent.AddedKey) error {
	log.Println("Add()", key.Comment)

	s.mu.Lock()
	defer s.mu.Unlock()

	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		log.Fatalf("newsignerfromkey failed: %s", err)
	}
	s.keys = append(s.keys, &sshKey{
		signer:  signer,
		comment: key.Comment,
		pk:      key.PrivateKey,
	})
	return nil
}

func (s *SSHAgent) Remove(key ssh.PublicKey) error {
	log.Println("Remove()", key)

	s.mu.Lock()
	defer s.mu.Unlock()

	var keys []*sshKey

	for _, k := range s.keys {
		if !bytes.Equal(k.signer.PublicKey().Marshal(), key.Marshal()) {
			keys = append(keys, k)
		}
	}
	s.keys = keys
	return nil
}

func (*SSHAgent) RemoveAll() error {
	return fmt.Errorf("implement me")
}

func (*SSHAgent) Lock(passphrase []byte) error {
	return fmt.Errorf("implement me")
}

func (*SSHAgent) Unlock(passphrase []byte) error {
	return fmt.Errorf("implement me")
}

func (*SSHAgent) Signers() ([]ssh.Signer, error) {
	return nil, fmt.Errorf("implement me")
}

func (s *SSHAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	if extensionType == "ssh-ed25519-decrypt@age-tool.com" {
		for _, k := range s.keys {
			if bytes.Equal(k.signer.PublicKey().Marshal(), contents[32:]) {
				return handleAgeDecrypt(k, contents)
			}
		}
	}
	if extensionType == "ssh-rsa-decrypt@age-tool.com" {
		for _, k := range s.keys {
			mk := k.signer.PublicKey().Marshal()
			if len(contents) > len(mk) && bytes.Equal(mk, contents[:len(mk)]) {
				pk := k.pk.(*rsa.PrivateKey)
				fileKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, pk, contents[len(mk):], []byte(oaepLabel))
				if err != nil {
					return nil, fmt.Errorf("failed to decrypt file key: %v", err)
				}
				return fileKey, nil
			}
		}
	}
	return nil, agent.ErrExtensionUnsupported
}

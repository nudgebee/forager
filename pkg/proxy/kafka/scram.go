package kafka

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/xdg-go/scram"
)

// scramClient implements sarama.SCRAMClient for SCRAM-SHA-256 and SCRAM-SHA-512.
type scramClient struct {
	mechanism string
	conv      *scram.ClientConversation
}

func (s *scramClient) Begin(userName, password, authzID string) error {
	var hashGen scram.HashGeneratorFcn
	switch s.mechanism {
	case "SHA-512":
		hashGen = func() hash.Hash { return sha512.New() }
	default:
		hashGen = func() hash.Hash { return sha256.New() }
	}

	client, err := hashGen.NewClient(userName, password, authzID)
	if err != nil {
		return err
	}
	s.conv = client.NewConversation()
	return nil
}

func (s *scramClient) Step(challenge string) (string, error) {
	return s.conv.Step(challenge)
}

func (s *scramClient) Done() bool {
	return s.conv.Done()
}

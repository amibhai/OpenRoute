package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

// Chrome Native Messaging: each message is a 4-byte length prefix in native
// byte order (little-endian on every platform Chrome ships on) followed by that
// many bytes of UTF-8 JSON. Chrome caps a single message at 1 MiB.
const maxMessage = 1 << 20

func readMessage(r io.Reader) (map[string]any, error) {
	var lenb [4]byte
	if _, err := io.ReadFull(r, lenb[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(lenb[:])
	if n == 0 || n > maxMessage {
		return nil, errors.New("invalid message length")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(buf, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func writeMessage(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxMessage {
		return errors.New("response exceeds 1 MiB")
	}
	var lenb [4]byte
	binary.LittleEndian.PutUint32(lenb[:], uint32(len(b)))
	if _, err := w.Write(lenb[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

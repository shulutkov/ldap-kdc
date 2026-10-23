package krbkeys

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// ErrTruncatedKeytab reports a keytab that ends inside an entry.
var ErrTruncatedKeytab = errors.New("keytab is truncated")

// ParseKeytab reads an MIT keytab version 2 file, the format MarshalKeytab writes. An empty input
// is an empty keytab. Holes, the entries a keytab editor marks as deleted by a negative size, are
// skipped.
func ParseKeytab(data []byte) ([]KeytabEntry, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < 2 || data[0] != 0x05 || data[1] != 0x02 {
		return nil, errors.New("not an MIT keytab, version 2")
	}

	var out []KeytabEntry

	rest := data[2:]
	for len(rest) > 0 {
		if len(rest) < 4 {
			return nil, ErrTruncatedKeytab
		}

		size := int64(int32(binary.BigEndian.Uint32(rest)))
		rest = rest[4:]

		if size < 0 {
			if -size > int64(len(rest)) {
				return nil, ErrTruncatedKeytab
			}
			rest = rest[-size:]

			continue
		}
		if size == 0 || size > int64(len(rest)) {
			return nil, ErrTruncatedKeytab
		}

		e, err := parseKeytabEntry(rest[:size])
		if err != nil {
			return nil, err
		}

		out = append(out, e)
		rest = rest[size:]
	}

	return out, nil
}

func parseKeytabEntry(b []byte) (KeytabEntry, error) {
	r := bytes.NewReader(b)

	var ncomp uint16
	if err := binary.Read(r, binary.BigEndian, &ncomp); err != nil {
		return KeytabEntry{}, ErrTruncatedKeytab
	}

	realm, err := readCountedString(r)
	if err != nil {
		return KeytabEntry{}, err
	}

	comps := make([]string, 0, ncomp)
	for range ncomp {
		c, err := readCountedString(r)
		if err != nil {
			return KeytabEntry{}, err
		}
		comps = append(comps, c)
	}

	// The name type is derived from the components again when the file is written, so it is read
	// only to advance past it.
	var nameType, ts uint32
	var kvno8 uint8
	var etype, keylen uint16
	for _, v := range []any{&nameType, &ts, &kvno8, &etype, &keylen} {
		if err := binary.Read(r, binary.BigEndian, v); err != nil {
			return KeytabEntry{}, ErrTruncatedKeytab
		}
	}

	key := make([]byte, keylen)
	if _, err := io.ReadFull(r, key); err != nil {
		return KeytabEntry{}, ErrTruncatedKeytab
	}

	kvno := int(kvno8)
	if r.Len() >= 4 {
		// The 32 bit kvno after the key carries the real value above 255; the 8 bit one is kept
		// for readers that predate it.
		var kvno32 uint32
		if err := binary.Read(r, binary.BigEndian, &kvno32); err != nil {
			return KeytabEntry{}, ErrTruncatedKeytab
		}
		kvno = int(kvno32)
	}

	return KeytabEntry{
		Name:      Name{Components: comps, Realm: realm},
		KVNO:      kvno,
		Key:       Key{EType: int32(etype), Value: key},
		Timestamp: time.Unix(int64(ts), 0),
	}, nil
}

func readCountedString(r *bytes.Reader) (string, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return "", ErrTruncatedKeytab
	}

	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", ErrTruncatedKeytab
	}

	return string(buf), nil
}

// MergeKeytab adds entries to a keytab the way ktadd does. An existing entry for the same
// principal, kvno and key type is replaced by the new one; everything else is kept in its order,
// and the added entries go last.
func MergeKeytab(existing, added []KeytabEntry) []KeytabEntry {
	replaced := make(map[string]bool, len(added))
	for _, e := range added {
		replaced[keytabEntryID(e)] = true
	}

	out := make([]KeytabEntry, 0, len(existing)+len(added))
	for _, e := range existing {
		if !replaced[keytabEntryID(e)] {
			out = append(out, e)
		}
	}

	return append(out, added...)
}

func keytabEntryID(e KeytabEntry) string {
	return fmt.Sprintf("%s@%s|%d|%d",
		strings.Join(e.Name.Components, "/"), e.Name.Realm, e.KVNO, e.Key.EType)
}

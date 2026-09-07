package krbkeys

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// KeytabEntry is one principal/kvno/key triple to write into a keytab file.
type KeytabEntry struct {
	Name      Name
	KVNO      int
	Key       Key
	Timestamp time.Time
}

// MarshalKeytab renders entries as an MIT keytab version 2 file.
//
// The library's keytab type derives its keys from a password, which cannot express the random keys
// this service issues to service principals, and its entry type is unexported so entries cannot be
// built directly. The format is small and stable, so it is written here instead:
//
//	0x05 0x02
//	repeated: int32 size, principal, uint32 timestamp, uint8 kvno8, uint16 keytype,
//	          uint16 keylen, key bytes, uint32 kvno32
//
// where a principal is int16 component count, counted-string realm, counted-string components and
// an int32 name type. All integers are big endian in version 2.
func MarshalKeytab(entries []KeytabEntry) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{0x05, 0x02})

	for _, e := range entries {
		eb, err := marshalKeytabEntry(e)
		if err != nil {
			return nil, err
		}
		buf.Write(eb)
	}

	return buf.Bytes(), nil
}

func marshalKeytabEntry(e KeytabEntry) ([]byte, error) {
	if len(e.Name.Components) == 0 {
		return nil, fmt.Errorf("keytab entry has no principal components")
	}
	if len(e.Name.Components) > 0x7fff {
		return nil, fmt.Errorf("keytab entry has too many principal components")
	}
	if len(e.Key.Value) > 0xffff {
		return nil, fmt.Errorf("keytab key is too long")
	}

	body := new(bytes.Buffer)

	_ = binary.Write(body, binary.BigEndian, int16(len(e.Name.Components)))

	if err := writeCountedString(body, e.Name.Realm); err != nil {
		return nil, err
	}
	for _, c := range e.Name.Components {
		if err := writeCountedString(body, c); err != nil {
			return nil, err
		}
	}

	_ = binary.Write(body, binary.BigEndian, e.Name.Type())

	ts := e.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	_ = binary.Write(body, binary.BigEndian, uint32(ts.Unix()))

	// The 8 bit kvno is the historical field; the 32 bit one at the end carries the real value
	// for kvnos above 255. Both are written, as MIT does.
	_ = binary.Write(body, binary.BigEndian, uint8(e.KVNO))
	_ = binary.Write(body, binary.BigEndian, uint16(e.Key.EType))
	_ = binary.Write(body, binary.BigEndian, uint16(len(e.Key.Value)))
	body.Write(e.Key.Value)
	_ = binary.Write(body, binary.BigEndian, uint32(e.KVNO))

	out := new(bytes.Buffer)
	_ = binary.Write(out, binary.BigEndian, int32(body.Len()))
	out.Write(body.Bytes())

	return out.Bytes(), nil
}

func writeCountedString(w *bytes.Buffer, s string) error {
	if len(s) > 0xffff {
		return fmt.Errorf("keytab string %q is too long", s)
	}

	_ = binary.Write(w, binary.BigEndian, uint16(len(s)))
	w.WriteString(s)

	return nil
}

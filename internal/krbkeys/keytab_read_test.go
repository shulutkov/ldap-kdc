package krbkeys

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func testEntry(t *testing.T, name string, kvno int, etype int32, fill byte) KeytabEntry {
	t.Helper()

	n, err := ParseName(name, "ADH.LOCAL")
	if err != nil {
		t.Fatal(err)
	}

	return KeytabEntry{
		Name:      n,
		KVNO:      kvno,
		Key:       Key{EType: etype, Value: bytes.Repeat([]byte{fill}, 32)},
		Timestamp: time.Unix(1_700_000_000, 0),
	}
}

func TestKeytabRoundTrip(t *testing.T) {
	in := []KeytabEntry{
		testEntry(t, "HTTP/nn.adh.local", 3, 18, 0xaa),
		testEntry(t, "hdfs", 300, 17, 0xbb), // kvno above 255 needs the 32 bit field
	}

	blob, err := MarshalKeytab(in)
	if err != nil {
		t.Fatal(err)
	}

	out, err := ParseKeytab(blob)
	if err != nil {
		t.Fatal(err)
	}

	if len(out) != len(in) {
		t.Fatalf("parsed %d entries, want %d", len(out), len(in))
	}
	for i := range in {
		if got, want := keytabEntryID(out[i]), keytabEntryID(in[i]); got != want {
			t.Errorf("entry %d: id %q, want %q", i, got, want)
		}
		if !bytes.Equal(out[i].Key.Value, in[i].Key.Value) {
			t.Errorf("entry %d: key bytes differ", i)
		}
		if !out[i].Timestamp.Equal(in[i].Timestamp) {
			t.Errorf("entry %d: timestamp %v, want %v", i, out[i].Timestamp, in[i].Timestamp)
		}
	}
}

func TestParseKeytabEmptyAndHoles(t *testing.T) {
	if got, err := ParseKeytab(nil); err != nil || len(got) != 0 {
		t.Fatalf("empty input: %v, %v", got, err)
	}

	valid, err := MarshalKeytab([]KeytabEntry{testEntry(t, "hdfs", 1, 18, 0x01)})
	if err != nil {
		t.Fatal(err)
	}

	// A hole of four bytes after the version header, then the valid entry.
	hole := []byte{0x05, 0x02}
	hole = binary.BigEndian.AppendUint32(hole, uint32(0xfffffffc)) // -4
	hole = append(hole, 1, 2, 3, 4)
	hole = append(hole, valid[2:]...)

	got, err := ParseKeytab(hole)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || keytabEntryID(got[0]) != "hdfs@ADH.LOCAL|1|18" {
		t.Fatalf("holes not skipped: %+v", got)
	}
}

func TestParseKeytabRejectsOtherVersions(t *testing.T) {
	if _, err := ParseKeytab([]byte{0x05, 0x01}); err == nil {
		t.Fatal("version 1 keytab accepted")
	}
}

func TestParseKeytabRejectsTruncation(t *testing.T) {
	blob, err := MarshalKeytab([]KeytabEntry{testEntry(t, "hdfs", 1, 18, 0x01)})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ParseKeytab(blob[:len(blob)-5]); err == nil {
		t.Fatal("truncated keytab accepted")
	}
}

func TestMergeKeytabReplacesSameKVNOAndEType(t *testing.T) {
	old18 := testEntry(t, "HTTP/nn.adh.local", 1, 18, 0x01)
	old17 := testEntry(t, "HTTP/nn.adh.local", 1, 17, 0x02)
	other := testEntry(t, "hdfs", 1, 18, 0x03)
	fresh18 := testEntry(t, "HTTP/nn.adh.local", 1, 18, 0x09)

	merged := MergeKeytab([]KeytabEntry{old18, other, old17}, []KeytabEntry{fresh18})

	want := []string{
		"hdfs@ADH.LOCAL|1|18",
		"HTTP/nn.adh.local@ADH.LOCAL|1|17",
		"HTTP/nn.adh.local@ADH.LOCAL|1|18",
	}
	if len(merged) != len(want) {
		t.Fatalf("merged %d entries, want %d", len(merged), len(want))
	}
	for i := range want {
		if got := keytabEntryID(merged[i]); got != want[i] {
			t.Errorf("entry %d: %q, want %q", i, got, want[i])
		}
	}
	if merged[2].Key.Value[0] != 0x09 {
		t.Error("the added entry did not replace the existing one")
	}
}

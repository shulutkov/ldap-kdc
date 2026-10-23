package store

import (
	"context"
	"errors"
	"testing"
)

// TestDiscoveredRecordsBelongToTheirOrigin: an administrator's record and a registration are told
// apart by origin, and only the side that owns a record can remove it.
func TestDiscoveredRecordsBelongToTheirOrigin(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	admin := &DNSRecord{Name: "admin.example.com", Type: "A", Value: "192.0.2.1", TTL: 60}
	if err := s.CreateDNSRecord(ctx, admin); err != nil {
		t.Fatalf("CreateDNSRecord: %v", err)
	}

	reg := &DNSRecord{Name: "web.example.com", Type: "A", Value: "10.0.0.5", TTL: 60}
	if err := s.CreateDiscoveredDNSRecord(ctx, "docker:web-id", reg); err != nil {
		t.Fatalf("CreateDiscoveredDNSRecord: %v", err)
	}

	// The API path cannot mint a registration: an origin set on an administrator's record is dropped.
	forged := &DNSRecord{Name: "forged.example.com", Type: "A", Value: "10.0.0.6", TTL: 60, Origin: "docker:x"}
	if err := s.CreateDNSRecord(ctx, forged); err != nil {
		t.Fatalf("CreateDNSRecord with an origin: %v", err)
	}
	if forged.Origin != "" {
		t.Errorf("administrator's record kept origin %q", forged.Origin)
	}

	list, _ := s.ListDiscoveredDNSRecords(ctx, "docker")
	if len(list) != 1 || list[0].Name != "web.example.com" || list[0].Origin != "docker:web-id" {
		t.Errorf("discovered = %+v, want only web", list)
	}

	// The administrator cannot remove a registration by id, nor by name.
	if err := s.DeleteDNSRecord(ctx, reg.ID); !errors.Is(err, ErrConflict) {
		t.Errorf("DeleteDNSRecord of a registration = %v, want ErrConflict", err)
	}
	if _, err := s.DeleteDNSRecordsAt(ctx, "web.example.com", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteDNSRecordsAt over a registration = %v, want ErrNotFound", err)
	}

	// A registration cannot be removed as though it were an administrator's.
	if err := s.DeleteDiscoveredDNSRecord(ctx, admin.ID); !errors.Is(err, ErrConflict) {
		t.Errorf("DeleteDiscoveredDNSRecord of an administrator's record = %v, want ErrConflict", err)
	}

	if err := s.DeleteDiscoveredDNSRecord(ctx, reg.ID); err != nil {
		t.Fatalf("DeleteDiscoveredDNSRecord: %v", err)
	}
	if err := s.DeleteDiscoveredDNSRecord(ctx, reg.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting a registration twice = %v, want ErrNotFound", err)
	}
}

func TestDiscoveredRecordNeedsAnOrigin(t *testing.T) {
	s := testStore(t)

	r := &DNSRecord{Name: "web.example.com", Type: "A", Value: "10.0.0.5", TTL: 60}
	if err := s.CreateDiscoveredDNSRecord(context.Background(), "", r); err == nil {
		t.Error("a registration without an origin was stored")
	}
}

// TestZoneSerialRisesWithEveryChange, removals included: a secondary comparing serials must see a
// record taken away, which the old insert-time serial never showed.
func TestZoneSerialRisesWithEveryChange(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)

	start, err := s.ZoneSerial(ctx)
	if err != nil {
		t.Fatalf("ZoneSerial: %v", err)
	}

	r := &DNSRecord{Name: "a.example.com", Type: "A", Value: "192.0.2.1", TTL: 60}
	if err := s.CreateDNSRecord(ctx, r); err != nil {
		t.Fatalf("CreateDNSRecord: %v", err)
	}
	afterInsert, _ := s.ZoneSerial(ctx)

	if err := s.DeleteDNSRecord(ctx, r.ID); err != nil {
		t.Fatalf("DeleteDNSRecord: %v", err)
	}
	afterDelete, _ := s.ZoneSerial(ctx)

	if !(start < afterInsert && afterInsert < afterDelete) {
		t.Errorf("serials %d, %d, %d: want each change to raise the serial", start, afterInsert, afterDelete)
	}
}

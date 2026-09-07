package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/shulutkov/ldap-kdc/internal/dnssrv"
	"github.com/shulutkov/ldap-kdc/internal/store"
)

// createDNSRecordRequest adds one resource record to the realm's zone.
type createDNSRecordRequest struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// Value is the record data in the form a zone file would use: "192.0.2.10" for an A record,
	// "0 100 88 kdc.example.com." for an SRV.
	Value string `json:"value"`
	// TTL defaults to the zone's when omitted.
	TTL int `json:"ttl,omitempty"`
}

func (s *Server) handleListDNSRecords(w http.ResponseWriter, r *http.Request) {
	records, err := s.st.ListDNSRecords(r.Context())
	if err != nil {
		writeStoreError(w, err)

		return
	}

	if name := r.URL.Query().Get("name"); len(name) > 0 {
		if records, err = s.st.LookupDNSRecords(r.Context(), name); err != nil {
			writeStoreError(w, err)

			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"records": records, "zones": s.cfg.DNSZones})
}

func (s *Server) handleCreateDNSRecord(w http.ResponseWriter, r *http.Request) {
	var req createDNSRecordRequest
	if !decode(w, r, &req) {
		return
	}

	record := store.DNSRecord{
		Name:  req.Name,
		Type:  strings.ToUpper(strings.TrimSpace(req.Type)),
		Value: req.Value,
		TTL:   req.TTL,
	}

	if record.TTL <= 0 {
		record.TTL = s.cfg.DNSDefaultTTL
	}

	if err := dnssrv.ValidateRecord(record); err != nil {
		writeError(w, http.StatusBadRequest, "%s", err)

		return
	}

	// A record outside every served zone would be stored and never answered, which is a
	// setting that looks applied and is not.
	if len(s.cfg.DNSZones) > 0 && !dnssrv.InZone(record.Name, s.cfg.DNSZones) {
		writeError(w, http.StatusBadRequest,
			"%s is outside the zones this server answers for (%s)",
			record.Name, strings.Join(s.cfg.DNSZones, ", "))

		return
	}

	if err := s.st.CreateDNSRecord(r.Context(), &record); err != nil {
		writeStoreError(w, err)

		return
	}

	s.log.Info().Str("name", record.Name).Str("type", record.Type).Str("value", record.Value).
		Msg("DNS record created")
	writeJSON(w, http.StatusCreated, map[string]any{"record": record})
}

func (s *Server) handleDeleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "record id must be a number")

		return
	}

	if err := s.st.DeleteDNSRecord(r.Context(), id); err != nil {
		writeStoreError(w, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

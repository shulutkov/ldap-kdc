// Package metrics holds the Prometheus collectors shared by the service's front ends.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics groups every collector the service exports.
type Metrics struct {
	Registry *prometheus.Registry

	LDAPBinds        *prometheus.CounterVec
	LDAPSearches     *prometheus.CounterVec
	LDAPDuration     *prometheus.HistogramVec
	KDCRequests      *prometheus.CounterVec
	KDCDuration      *prometheus.HistogramVec
	KDCTicketsIssued *prometheus.CounterVec
	KPasswdRequests  *prometheus.CounterVec
	APIRequests      *prometheus.CounterVec
	OIDCRequests     *prometheus.CounterVec
	DNSQueries       *prometheus.CounterVec
	DNSDuration      prometheus.Histogram
}

// New builds the collectors and registers them, alongside the standard Go and process collectors.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		Registry: reg,
		LDAPBinds: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ldap_binds_total",
			Help: "LDAP bind attempts by result.",
		}, []string{"result"}),
		LDAPSearches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ldap_searches_total",
			Help: "LDAP search operations by result.",
		}, []string{"result"}),
		LDAPDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "ldap_operation_duration_seconds",
			Help:    "Time spent handling an LDAP operation.",
			Buckets: prometheus.DefBuckets,
		}, []string{"operation"}),
		KDCRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kdc_requests_total",
			Help: "Kerberos KDC requests by exchange and result.",
		}, []string{"exchange", "result"}),
		KDCDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "kdc_request_duration_seconds",
			Help:    "Time spent handling a Kerberos request.",
			Buckets: prometheus.DefBuckets,
		}, []string{"exchange"}),
		KDCTicketsIssued: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kdc_tickets_issued_total",
			Help: "Tickets issued by kind.",
		}, []string{"kind"}),
		KPasswdRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "kpasswd_requests_total",
			Help: "Password change requests by result.",
		}, []string{"result"}),
		APIRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "api_requests_total",
			Help: "REST API requests by method, route and status.",
		}, []string{"method", "route", "status"}),
		OIDCRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "oidc_requests_total",
			Help: "OpenID Connect operations by kind and result.",
		}, []string{"operation", "result"}),
		DNSQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "dns_queries_total",
			Help: "DNS queries by record type and response code.",
		}, []string{"type", "rcode"}),
		DNSDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "dns_query_duration_seconds",
			Help:    "Time spent answering a DNS query.",
			Buckets: prometheus.DefBuckets,
		}),
	}

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.LDAPBinds, m.LDAPSearches, m.LDAPDuration,
		m.KDCRequests, m.KDCDuration, m.KDCTicketsIssued,
		m.KPasswdRequests, m.APIRequests, m.OIDCRequests, m.DNSQueries, m.DNSDuration,
	)

	return m
}

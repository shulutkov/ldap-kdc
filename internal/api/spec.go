package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/swaggest/openapi-go"
	"github.com/swaggest/openapi-go/openapi3"
)

// The OpenAPI document is built from the route table and the Go types the handlers decode and
// encode, once, when the service starts.
//
// Generating it is what keeps it true. A field renamed in a request struct changes the document in
// the same commit, and there is no second description of this API to fall out of step with the
// first -- which matters, because a stale document is not ignored, it is believed. What reflection
// cannot know is the prose: what an endpoint is for, why a password is expired by default. That
// lives in the route table below and in `description` tags on the fields themselves.

const securityScheme = "bearerAuth"

// operationDoc describes one operation to a reader of the document.
//
// A route usually carries one. The principal routes carry several, because a service name contains
// slashes and one trailing-wildcard pattern therefore serves the principal and every action under
// it; the document spells those out as the separate paths they are.
type operationDoc struct {
	// path overrides the router's own pattern, for the actions matched inside a handler.
	path        string
	tag         string
	summary     string
	description string
	// request is a value whose fields carry the path parameters, query parameters and JSON body
	// the operation accepts.
	request   any
	responses []responseDoc
	// public marks an operation that needs no bearer token.
	public bool
}

// responseDoc is one answer an operation can give.
type responseDoc struct {
	status int
	// body is nil when the answer carries none, as a 204 does.
	body        any
	description string
	// contentType is for the answers that are not JSON.
	contentType string
}

// ok, created and noContent are the shapes of the common answers.
func ok(body any, description string) responseDoc {
	return responseDoc{status: http.StatusOK, body: body, description: description}
}

func created(body any, description string) responseDoc {
	return responseDoc{status: http.StatusCreated, body: body, description: description}
}

func noContent(description string) responseDoc {
	return responseDoc{status: http.StatusNoContent, description: description}
}

// failures are the refusals every authenticated operation can produce. They are listed per
// operation rather than added to all of them, so the document says which ones can actually happen.
var (
	badRequest   = responseDoc{status: http.StatusBadRequest, body: new(errorBody), description: "The request was malformed or refused by policy."}
	unauthorized = responseDoc{status: http.StatusUnauthorized, body: new(errorBody), description: "A valid bearer token is required."}
	notFound     = responseDoc{status: http.StatusNotFound, body: new(errorBody), description: "No such object."}
	conflict     = responseDoc{status: http.StatusConflict, body: new(errorBody), description: "The object exists, or the name is already taken."}
)

// Path and query parameters, declared as the structures the reflector reads them from.

type userPath struct {
	Name string `path:"name" description:"The account's name." example:"alice"`
}

type appPasswordPath struct {
	Name string `path:"name" description:"The account's name." example:"alice"`
	ID   int64  `path:"id" description:"The application password's identifier."`
}

type groupPath struct {
	Name string `path:"name" description:"The group's name." example:"staff"`
}

type principalPath struct {
	Name string `path:"name" description:"With or without a realm. A service name carries slashes, which are part of the name." example:"HTTP/www.example.com"`
}

type trustPath struct {
	Realm string `path:"realm" description:"The remote realm." example:"PARTNER.COM"`
}

type dnsRecordPath struct {
	ID int64 `path:"id" description:"The record's identifier."`
}

type principalsQuery struct {
	Realm string `query:"realm" description:"Restrict the answer to one realm."`
}

type dnsRecordsQuery struct {
	Name string `query:"name" description:"Return only the records at this name."`
}

// The request structures, which pair the parameters an operation takes with the body it accepts.

type getUserReq struct{ userPath }

type patchUserReq struct {
	userPath
	patchUserRequest
}

type setUserPasswordReq struct {
	userPath
	setPasswordRequest
}

type appPasswordReq struct {
	userPath
	appPasswordRequest
}

type patchGroupReq struct {
	groupPath
	patchGroupRequest
}

type patchPrincipalReq struct {
	principalPath
	patchPrincipalRequest
}

type principalPasswordReq struct {
	principalPath
	principalPasswordRequest
}

type patchTrustReq struct {
	trustPath
	patchTrustRequest
}

// keytabFile is the body of a keytab download, described as the opaque file it is.
type keytabFile struct {
	_ struct{} `contentType:"application/octet-stream"`
}

// buildSpec renders the document for the routes this server serves.
func (s *Server) buildSpec() ([]byte, error) {
	reflector := openapi3.NewReflector()
	spec := reflector.SpecEns()

	spec.Info.
		WithTitle("ldap-kdc management API").
		WithVersion("v1").
		WithDescription(apiDescription)

	spec.SetHTTPBearerTokenSecurity(securityScheme, "",
		"The token from api.token in the configuration. With no token configured the API is open and this is ignored.")

	spec.WithTags(
		openapi3.Tag{Name: "users", Description: strPtr("Directory accounts and their credentials.")},
		openapi3.Tag{Name: "groups", Description: strPtr("POSIX groups, which may include other groups.")},
		openapi3.Tag{Name: "principals", Description: strPtr("Kerberos identities: policy, keys and keytabs.")},
		openapi3.Tag{Name: "dns", Description: strPtr("The realm's zone, from which reverse answers are derived.")},
		openapi3.Tag{Name: "trusts", Description: strPtr("Cross-realm relationships.")},
		openapi3.Tag{Name: "operations", Description: strPtr("Health, readiness and a summary of what the directory holds.")},
	)

	for _, r := range append(s.publicRoutes(), s.apiRoutes()...) {
		method, pattern, _ := strings.Cut(r.pattern, " ")

		for _, d := range r.docs {
			if err := addOperation(reflector, method, documentedPath(pattern, d), d); err != nil {
				return nil, err
			}
		}
	}

	return json.MarshalIndent(spec, "", "  ")
}

// documentedPath is the path an operation appears under: its own when it names one, and otherwise
// the router's pattern with Go's trailing wildcard spelled the way OpenAPI spells a parameter.
func documentedPath(pattern string, d operationDoc) string {
	if len(d.path) > 0 {
		return d.path
	}

	return strings.ReplaceAll(pattern, "...}", "}")
}

// addOperation reflects one operation into the document.
func addOperation(reflector *openapi3.Reflector, method, path string, d operationDoc) error {
	oc, err := reflector.NewOperationContext(method, path)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}

	oc.SetTags(d.tag)
	oc.SetSummary(d.summary)
	oc.SetDescription(d.description)

	if d.request != nil {
		oc.AddReqStructure(d.request)
	}

	if !d.public {
		oc.AddSecurity(securityScheme)
	}

	for _, resp := range d.responses {
		body := resp.body
		if body == nil {
			// A status with no body still has to appear, or a client generated from this
			// document treats it as an error it was never told about.
			body = struct{}{}
		}

		options := []openapi.ContentOption{
			func(cu *openapi.ContentUnit) {
				cu.HTTPStatus = resp.status
				cu.Description = resp.description
			},
		}
		if len(resp.contentType) > 0 {
			options = append(options, openapi.WithContentType(resp.contentType))
		}

		oc.AddRespStructure(body, options...)
	}

	return reflector.AddOperation(oc)
}

func strPtr(s string) *string { return &s }

// apiDescription is the document's preamble: what this service is, and the one thing a reader has
// to know before using any of it.
const apiDescription = "The REST interface to one directory served over both LDAP and Kerberos.\n\n" +
	"Every write here reaches both sides at once. Setting a password stores the bcrypt digest an " +
	"LDAP simple bind compares against and the long-term keys a Kerberos AS exchange needs: one " +
	"cannot be derived from the other, and an account holding only one of them authenticates over " +
	"one protocol and not the other.\n\n" +
	"Requests under `/api` carry `Authorization: Bearer <token>` when the service is configured " +
	"with one. The probes, the metrics and this documentation never require it."

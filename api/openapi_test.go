// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package api_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/siderolabs/image-factory/api"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	document, err := api.Load(t.Context())
	require.NoError(t, err)

	assert.Equal(t, "3.1.0", document.OpenAPI)
	assert.Equal(t, "https://spec.openapis.org/oas/3.1/dialect/2024-11-10", document.JSONSchemaDialect)
	require.NotNil(t, document.Info)
	assert.Equal(t, "Image Factory API", document.Info.Title)
	require.NotNil(t, document.Paths)

	versions := document.Paths.Find("/versions")
	require.NotNil(t, versions)
	require.NotNil(t, versions.Get)
	assert.Equal(t, "listVersions", versions.Get.OperationID)
}

func TestSourceSpecificationIsModular(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("openapi.yaml")
	require.NoError(t, err)

	assert.Contains(t, string(source), `$ref: "./openapi/paths/`)
	assert.Contains(t, string(source), `$ref: "./openapi/components/`)
	assert.NotContains(t, string(source), "operationId:")
}

func TestSpecificationIsSelfContained(t *testing.T) {
	t.Parallel()

	specification, err := api.Specification()
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(specification), `$ref: "./openapi/`))

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = false

	document, err := loader.LoadFromData(specification)
	require.NoError(t, err)
	require.NoError(t, document.Validate(t.Context(), openapi3.EnableMultiError()))

	secondSpecification, err := api.Specification()
	require.NoError(t, err)
	assert.Equal(t, specification, secondSpecification)

	specification[0] ^= 0xff

	thirdSpecification, err := api.Specification()
	require.NoError(t, err)
	assert.Equal(t, secondSpecification, thirdSpecification)
}

func TestDocumentationSchemas(t *testing.T) {
	t.Parallel()

	document, err := api.Load(t.Context())
	require.NoError(t, err)

	schematic := document.Components.Schemas["Schematic"].Value
	require.NotNil(t, schematic)
	assert.NotEmpty(t, schematic.Description)
	assert.NotEmpty(t, schematic.Examples)

	versions := document.Components.Schemas["VersionList"].Value
	require.NotNil(t, versions)
	require.NotNil(t, versions.Items)
	require.NotNil(t, versions.Items.Value)
	assert.NotEmpty(t, versions.Items.Value.Pattern)
	assert.NotEmpty(t, versions.Examples)

	parameters := document.Components.Parameters
	assert.NotEmpty(t, parameters["TalosVersion"].Value.Schema.Value.Pattern)
	assert.NotNil(t, parameters["TalosVersion"].Value.Example)
	assert.NotNil(t, parameters["ArtifactPath"].Value.Example)
	assert.Equal(t, `.+\.(json|table|sarif|cdx)$`, parameters["ScanReport"].Value.Schema.Value.Pattern)
	assert.NotNil(t, parameters["RegistryNameTail"].Value.Example)
	assert.NotEmpty(t, parameters["OCIReference"].Value.Schema.Value.OneOf)
	assert.NotEmpty(t, parameters["OCIDigest"].Value.Schema.Value.Pattern)

	downloadToken := document.Paths.Find("/download-token").Post
	require.NotNil(t, downloadToken)
	ttl := downloadToken.Parameters.GetByInAndName(openapi3.ParameterInQuery, "ttl")
	require.NotNil(t, ttl)
	assert.Equal(t, "1h", ttl.Example)
}

func TestEndpointDocumentationMetadata(t *testing.T) {
	t.Parallel()

	document, err := api.Load(t.Context())
	require.NoError(t, err)
	require.NotEmpty(t, document.Tags)

	declaredTags := make(map[string]struct{}, len(document.Tags))
	for _, tag := range document.Tags {
		declaredTags[tag.Name] = struct{}{}
		assert.NotEmpty(t, tag.Description, "tag %s must describe its API group", tag.Name)
	}

	for path, pathItem := range document.Paths.Map() {
		for method, operation := range pathItem.Operations() {
			require.Len(t, operation.Tags, 1, "%s %s must have exactly one documentation tag", method, path)
			_, ok := declaredTags[operation.Tags[0]]
			assert.True(t, ok, "%s %s uses undeclared tag %q", method, path, operation.Tags[0])
			assert.NotEmpty(t, operation.Description, "%s %s must have an endpoint description", method, path)

			security := document.Security
			if operation.Security != nil {
				security = *operation.Security
			}

			if len(security) == 0 {
				continue
			}

			value, ok := operation.Extensions["x-image-factory-access"]
			require.True(t, ok, "%s %s must document Image Factory access behavior", method, path)
			access, ok := value.(map[string]any)
			require.True(t, ok, "%s %s access metadata must be an object", method, path)
			assert.Contains(t, []any{"allowed", "denied"}, access["machineScope"], "%s %s has invalid machineScope", method, path)
			assert.Contains(t, []any{"conditional", "enforced", "not-applicable", "sets-owner"}, access["ownership"], "%s %s has invalid ownership", method, path)

			if operation.Tags[0] == "OCI Registry API" && strings.Contains(path, "{name+}") {
				assert.Equal(t, "conditional", access["ownership"], "%s %s must document repository-dependent ownership", method, path)
				assert.NotEmpty(t, access["ownershipDescription"], "%s %s must explain conditional ownership", method, path)
			}
		}
	}
}

func TestEnterpriseDocumentationMarkers(t *testing.T) {
	t.Parallel()

	document, err := api.Load(t.Context())
	require.NoError(t, err)

	for path, pathItem := range document.Paths.Map() {
		for method, operation := range pathItem.Operations() {
			marked, ok := operation.Extensions["x-enterprise"].(bool)
			assert.Equal(t, operation.Tags[0] == "Enterprise Frontend API", ok && marked, "%s %s", method, path)
		}
	}

	requireEnterpriseMarker(t, "parameter DownloadToken", document.Components.Parameters["DownloadToken"].Value.Extensions)
	requireEnterpriseMarker(t, "schema DownloadToken", document.Components.Schemas["DownloadToken"].Value.Extensions)
	requireEnterpriseMarker(t, "schema Schematic.owner", document.Components.Schemas["Schematic"].Value.Properties["owner"].Value.Extensions)

	for _, name := range []string{"SPDXResponse", "Unauthorized", "PaymentRequired", "Forbidden"} {
		requireEnterpriseMarker(t, "response "+name, document.Components.Responses[name].Value.Extensions)
	}

	for _, name := range []string{"basicAuth", "bearerAuth", "downloadToken"} {
		requireEnterpriseMarker(t, "security scheme "+name, document.Components.SecuritySchemes[name].Value.Extensions)
	}
}

func requireEnterpriseMarker(t *testing.T, component string, extensions map[string]any) {
	t.Helper()

	marked, ok := extensions["x-enterprise"].(bool)
	assert.True(t, ok && marked, "%s must set x-enterprise: true", component)
}

func TestUserFacingOperations(t *testing.T) {
	t.Parallel()

	document, err := api.Load(t.Context())
	require.NoError(t, err)

	expected := map[string]map[string]string{
		"/.well-known/jwks.json": {
			http.MethodGet: "getDownloadTokenJWKS",
		},
		"/download-token": {
			http.MethodPost: "createDownloadToken",
		},
		"/image/{schematic}/{version}/{path}": {
			http.MethodGet:  "getImage",
			http.MethodHead: "headImage",
		},
		"/llms.txt": {
			http.MethodGet: "getLLMsText",
		},
		"/oci/cosign/signing-key.pub": {
			http.MethodGet: "getCosignSigningKey",
		},
		"/openapi.yaml": {
			http.MethodGet: "getOpenAPI",
		},
		"/pxe/{schematic}/{version}/{path}": {
			http.MethodGet: "getPXEScript",
		},
		"/scans/{schematic}/{version}/{arch}/{report}": {
			http.MethodGet:  "getVulnerabilityScan",
			http.MethodHead: "headVulnerabilityScan",
		},
		"/schematics": {
			http.MethodPost: "createSchematic",
		},
		"/schematics/{schematic}": {
			http.MethodGet: "getSchematic",
		},
		"/secureboot/signing-cert.pem": {
			http.MethodGet: "getSecureBootSigningCertificate",
		},
		"/spdx/{schematic}/{version}/{arch}": {
			http.MethodGet:  "getSPDX",
			http.MethodHead: "headSPDX",
		},
		"/talosctl/{version}": {
			http.MethodGet: "listTalosctlDownloads",
		},
		"/talosctl/{version}/{path}": {
			http.MethodGet:  "getTalosctl",
			http.MethodHead: "headTalosctl",
		},
		"/v2": {
			http.MethodGet:  "checkRegistry",
			http.MethodHead: "headRegistry",
		},
		"/v2/": {
			http.MethodGet:  "checkRegistrySlash",
			http.MethodHead: "headRegistrySlash",
		},
		"/v2/{name+}/blobs/{digest}": {
			http.MethodGet:  "getRegistryBlob",
			http.MethodHead: "headRegistryBlob",
		},
		"/v2/{name+}/manifests/{reference}": {
			http.MethodGet:  "getRegistryManifest",
			http.MethodHead: "headRegistryManifest",
		},
		"/v2/{name+}/referrers/{digest}": {
			http.MethodGet:  "getRegistryReferrers",
			http.MethodHead: "headRegistryReferrers",
		},
		"/v2/{name+}/tags/list": {
			http.MethodGet:  "listRegistryTags",
			http.MethodHead: "headRegistryTags",
		},
		"/version/{version}/extensions/official": {
			http.MethodGet: "listOfficialExtensions",
		},
		"/version/{version}/overlays/official": {
			http.MethodGet: "listOfficialOverlays",
		},
		"/versions": {
			http.MethodGet: "listVersions",
		},
		"/vex/{version}/vex.json": {
			http.MethodGet:  "getVEX",
			http.MethodHead: "headVEX",
		},
	}

	actualCount := 0

	for path, methods := range expected {
		pathItem := document.Paths.Find(path)
		require.NotNil(t, pathItem, "missing OpenAPI path %s", path)

		for method, operationID := range methods {
			operation := pathItem.GetOperation(method)
			require.NotNil(t, operation, "missing OpenAPI operation %s %s", method, path)
			assert.Equal(t, operationID, operation.OperationID, "%s %s", method, path)
			require.NotNil(t, operation.Responses.Value("500"), "missing 500 response for %s %s", method, path)
		}
	}

	for path := range document.Paths.Map() {
		actualCount += len(document.Paths.Value(path).Operations())
	}

	expectedCount := 0
	for _, methods := range expected {
		expectedCount += len(methods)
	}

	assert.Equal(t, expectedCount, actualCount, "the contract must not contain undocumented user-facing operations")
}

func TestNewRouter(t *testing.T) {
	t.Parallel()

	router, err := api.NewRouter(t.Context())
	require.NoError(t, err)

	testRoute := func(name, method, target, operationID string, expectedParams map[string]string) {
		t.Helper()

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(t.Context(), method, target, nil)
			route, pathParams, routeErr := router.FindRoute(request)
			require.NoError(t, routeErr)
			require.NotNil(t, route.Operation)
			assert.Equal(t, operationID, route.Operation.OperationID)
			assert.Equal(t, expectedParams, pathParams)
		})
	}

	testRoute("static", http.MethodGet, "/versions", "listVersions", map[string]string{})
	testRoute(
		"artifact",
		http.MethodHead,
		"/image/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/v1.12.0/metal-amd64.raw.xz",
		"headImage",
		map[string]string{
			"schematic": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"version":   "v1.12.0",
			"path":      "metal-amd64.raw.xz",
		},
	)
	testRoute(
		"nested OCI manifest repository name",
		http.MethodGet,
		"/v2/my-company/platform/backend/manifests/v1.12.0",
		"getRegistryManifest",
		map[string]string{
			"name":      "my-company/platform/backend",
			"reference": "v1.12.0",
		},
	)
	testRoute(
		"nested OCI blob repository name",
		http.MethodGet,
		"/v2/my-company/platform/backend/blobs/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"getRegistryBlob",
		map[string]string{
			"name":   "my-company/platform/backend",
			"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	)
	testRoute(
		"nested OCI tags repository name",
		http.MethodGet,
		"/v2/my-company/platform/backend/tags/list",
		"listRegistryTags",
		map[string]string{
			"name": "my-company/platform/backend",
		},
	)
	testRoute(
		"nested OCI referrers repository name",
		http.MethodGet,
		"/v2/my-company/platform/backend/referrers/sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"getRegistryReferrers",
		map[string]string{
			"name":   "my-company/platform/backend",
			"digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	)
	testRoute("registry trailing slash", http.MethodHead, "/v2/", "headRegistrySlash", map[string]string{})
}

func TestContractValidateRequest(t *testing.T) {
	t.Parallel()

	contract, err := api.NewContract(t.Context())
	require.NoError(t, err)

	tests := []struct {
		name    string
		method  string
		target  string
		body    string
		headers map[string]string
		wantErr string
	}{
		{
			name:   "valid schematic",
			method: http.MethodPost,
			target: "/schematics",
			body:   `{"customization":{"extraKernelArgs":["console=ttyS0"]}}`,
			headers: map[string]string{
				"Content-Type": "application/json",
			},
		},
		{
			name:   "unknown schematic field",
			method: http.MethodPost,
			target: "/schematics",
			body:   `{"unknown":true}`,
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			wantErr: "property \"unknown\" is unsupported",
		},
		{
			name:   "handler-owned schematic path validation",
			method: http.MethodGet,
			target: "/schematics/not-a-digest",
		},
		{
			name:   "greedy OCI repository name",
			method: http.MethodGet,
			target: "/v2/my-company/platform/backend/manifests/v1.12.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(t.Context(), test.method, test.target, strings.NewReader(test.body))
			for name, value := range test.headers {
				request.Header.Set(name, value)
			}

			_, _, validationErr := contract.ValidateRequest(request.Context(), request)
			if test.wantErr == "" {
				require.NoError(t, validationErr)

				return
			}

			require.ErrorContains(t, validationErr, test.wantErr)
		})
	}
}

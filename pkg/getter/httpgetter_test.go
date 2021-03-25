/*
Copyright The Helm Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package getter

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"

	"helm.sh/helm/v3/internal/tlsutil"
	"helm.sh/helm/v3/internal/version"
	"helm.sh/helm/v3/pkg/cli"
)

func TestHTTPGetter(t *testing.T) {
	g, err := NewHTTPGetter(WithURL("http://example.com"))
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := g.(*HTTPGetter); !ok {
		t.Fatal("Expected NewHTTPGetter to produce an *HTTPGetter")
	}

	cd := "../../testdata"
	join := filepath.Join
	ca, pub, priv := join(cd, "rootca.crt"), join(cd, "crt.pem"), join(cd, "key.pem")
	insecure := false
	timeout := time.Second * 5

	// Test with options
	g, err = NewHTTPGetter(
		WithBasicAuth("I", "Am"),
		WithUserAgent("Groot"),
		WithTLSClientConfig(pub, priv, ca),
		WithInsecureSkipVerifyTLS(insecure),
		WithTimeout(timeout),
	)
	if err != nil {
		t.Fatal(err)
	}

	hg, ok := g.(*HTTPGetter)
	if !ok {
		t.Fatal("expected NewHTTPGetter to produce an *HTTPGetter")
	}

	if hg.opts.username != "I" {
		t.Errorf("Expected NewHTTPGetter to contain %q as the username, got %q", "I", hg.opts.username)
	}

	if hg.opts.password != "Am" {
		t.Errorf("Expected NewHTTPGetter to contain %q as the password, got %q", "Am", hg.opts.password)
	}

	if hg.opts.userAgent != "Groot" {
		t.Errorf("Expected NewHTTPGetter to contain %q as the user agent, got %q", "Groot", hg.opts.userAgent)
	}

	if hg.opts.certFile != pub {
		t.Errorf("Expected NewHTTPGetter to contain %q as the public key file, got %q", pub, hg.opts.certFile)
	}

	if hg.opts.keyFile != priv {
		t.Errorf("Expected NewHTTPGetter to contain %q as the private key file, got %q", priv, hg.opts.keyFile)
	}

	if hg.opts.caFile != ca {
		t.Errorf("Expected NewHTTPGetter to contain %q as the CA file, got %q", ca, hg.opts.caFile)
	}

	if hg.opts.insecureSkipVerifyTLS != insecure {
		t.Errorf("Expected NewHTTPGetter to contain %t as InsecureSkipVerifyTLs flag, got %t", false, hg.opts.insecureSkipVerifyTLS)
	}

	if hg.opts.timeout != timeout {
		t.Errorf("Expected NewHTTPGetter to contain %s as Timeout flag, got %s", timeout, hg.opts.timeout)
	}

	// Test if setting insecureSkipVerifyTLS is being passed to the ops
	insecure = true

	g, err = NewHTTPGetter(
		WithInsecureSkipVerifyTLS(insecure),
	)
	if err != nil {
		t.Fatal(err)
	}

	hg, ok = g.(*HTTPGetter)
	if !ok {
		t.Fatal("expected NewHTTPGetter to produce an *HTTPGetter")
	}

	if hg.opts.insecureSkipVerifyTLS != insecure {
		t.Errorf("Expected NewHTTPGetter to contain %t as InsecureSkipVerifyTLs flag, got %t", insecure, hg.opts.insecureSkipVerifyTLS)
	}
}

func TestDownload(t *testing.T) {
	expect := "Call me Ishmael"
	expectedUserAgent := "I am Groot"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defaultUserAgent := "Helm/" + strings.TrimPrefix(version.GetVersion(), "v")
		if r.UserAgent() != defaultUserAgent {
			t.Errorf("Expected '%s', got '%s'", defaultUserAgent, r.UserAgent())
		}
		fmt.Fprint(w, expect)
	}))
	defer srv.Close()

	g, err := All(cli.New()).ByScheme("http")
	if err != nil {
		t.Fatal(err)
	}
	got, err := g.Get(srv.URL, WithURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	if got.String() != expect {
		t.Errorf("Expected %q, got %q", expect, got.String())
	}

	// test with http server
	basicAuthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok || username != "username" || password != "password" {
			t.Errorf("Expected request to use basic auth and for username == 'username' and password == 'password', got '%v', '%s', '%s'", ok, username, password)
		}
		if r.UserAgent() != expectedUserAgent {
			t.Errorf("Expected '%s', got '%s'", expectedUserAgent, r.UserAgent())
		}
		fmt.Fprint(w, expect)
	}))

	defer basicAuthSrv.Close()

	u, _ := url.ParseRequestURI(basicAuthSrv.URL)
	httpgetter, err := NewHTTPGetter(
		WithURL(u.String()),
		WithBasicAuth("username", "password"),
		WithUserAgent(expectedUserAgent),
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err = httpgetter.Get(u.String())
	if err != nil {
		t.Fatal(err)
	}

	if got.String() != expect {
		t.Errorf("Expected %q, got %q", expect, got.String())
	}
}

func TestDownloadTLS(t *testing.T) {
	cd := "../../testdata"
	ca, pub, priv := filepath.Join(cd, "rootca.crt"), filepath.Join(cd, "crt.pem"), filepath.Join(cd, "key.pem")

	tlsSrv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	tlsConf, err := tlsutil.NewClientTLS(pub, priv, ca)
	if err != nil {
		t.Fatal(errors.Wrap(err, "can't create TLS config for client"))
	}
	tlsConf.BuildNameToCertificate()
	tlsConf.ServerName = "helm.sh"
	tlsSrv.TLS = tlsConf
	tlsSrv.StartTLS()
	defer tlsSrv.Close()

	u, _ := url.ParseRequestURI(tlsSrv.URL)
	g, err := NewHTTPGetter(
		WithURL(u.String()),
		WithTLSClientConfig(pub, priv, ca),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := g.Get(u.String()); err != nil {
		t.Error(err)
	}

	// now test with TLS config being passed along in .Get (see #6635)
	g, err = NewHTTPGetter()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := g.Get(u.String(), WithURL(u.String()), WithTLSClientConfig(pub, priv, ca)); err != nil {
		t.Error(err)
	}

	// test with only the CA file (see also #6635)
	g, err = NewHTTPGetter()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := g.Get(u.String(), WithURL(u.String()), WithTLSClientConfig("", "", ca)); err != nil {
		t.Error(err)
	}
}

func TestDownloadTLSWithRedirect(t *testing.T) {
	cd := "../../testdata"
	srv2Resp := "hello"

	// Server 2 that will actually fulfil the request.
	pub, priv := filepath.Join(cd, "localhost-crt.pem"), filepath.Join(cd, "key.pem")
	tlsConf, err := tlsutil.NewClientTLS(pub, priv, "")
	if err != nil {
		t.Fatal(errors.Wrap(err, "can't create TLS config for client"))
	}

	tlsSrv2 := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		rw.Write([]byte(srv2Resp))
	}))

	tlsSrv2.TLS = tlsConf
	tlsSrv2.StartTLS()
	defer tlsSrv2.Close()

	// Server 1 responds with a redirect to Server 2.
	ca, pub := filepath.Join(cd, "rootca.crt"), filepath.Join(cd, "crt.pem")
	tlsConf, err = tlsutil.NewClientTLS(pub, priv, ca)
	if err != nil {
		t.Fatal(errors.Wrap(err, "can't create TLS config for client"))
	}

	tlsSrv1 := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		u, _ := url.ParseRequestURI(tlsSrv2.URL)

		// Make the request using the hostname 'localhost' (to which 'localhost-crt.pem' is issued)
		// to verify that a successful TLS connection is made even if the client doesn't specify
		// the hostname (SNI) in `tls.Config.ServerName`. By default the hostname is derived from the
		// request URL for every request (including redirects). Setting `tls.Config.ServerName` on the
		// client just overrides the remote endpoint's hostname.
		// See https://golang.org/src/net/http/transport.go#L1505.
		u.Host = fmt.Sprintf("localhost:%s", u.Port())

		http.Redirect(rw, r, u.String(), http.StatusTemporaryRedirect)
	}))

	tlsSrv1.TLS = tlsConf
	tlsSrv1.StartTLS()
	defer tlsSrv1.Close()

	u, _ := url.ParseRequestURI(tlsSrv1.URL)

	t.Run("Test with TLS", func(t *testing.T) {
		g, err := NewHTTPGetter(
			WithURL(u.String()),
			WithTLSClientConfig(pub, priv, ca),
		)
		if err != nil {
			t.Fatal(err)
		}

		buf, err := g.Get(u.String())
		if err != nil {
			t.Error(err)
		}

		b, err := ioutil.ReadAll(buf)
		if err != nil {
			t.Error(err)
		}

		if string(b) != srv2Resp {
			t.Errorf("expected response from Server2 to be '%s', instead got: %s", srv2Resp, string(b))
		}
	})

	t.Run("Test with TLS config being passed along in .Get (see #6635)", func(t *testing.T) {
		g, err := NewHTTPGetter()
		if err != nil {
			t.Fatal(err)
		}

		buf, err := g.Get(u.String(), WithURL(u.String()), WithTLSClientConfig(pub, priv, ca))
		if err != nil {
			t.Error(err)
		}

		b, err := ioutil.ReadAll(buf)
		if err != nil {
			t.Error(err)
		}

		if string(b) != srv2Resp {
			t.Errorf("expected response from Server2 to be '%s', instead got: %s", srv2Resp, string(b))
		}
	})

	t.Run("Test with only the CA file (see also #6635)", func(t *testing.T) {
		g, err := NewHTTPGetter()
		if err != nil {
			t.Fatal(err)
		}

		buf, err := g.Get(u.String(), WithURL(u.String()), WithTLSClientConfig("", "", ca))
		if err != nil {
			t.Error(err)
		}

		b, err := ioutil.ReadAll(buf)
		if err != nil {
			t.Error(err)
		}

		if string(b) != srv2Resp {
			t.Errorf("expected response from Server2 to be '%s', instead got: %s", srv2Resp, string(b))
		}
	})
}

func TestDownloadInsecureSkipTLSVerify(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()

	u, _ := url.ParseRequestURI(ts.URL)

	// Ensure the default behaviour did not change
	g, err := NewHTTPGetter(
		WithURL(u.String()),
	)
	if err != nil {
		t.Error(err)
	}

	if _, err := g.Get(u.String()); err == nil {
		t.Errorf("Expected Getter to throw an error, got %s", err)
	}

	// Test certificate check skip
	g, err = NewHTTPGetter(
		WithURL(u.String()),
		WithInsecureSkipVerifyTLS(true),
	)
	if err != nil {
		t.Error(err)
	}
	if _, err = g.Get(u.String()); err != nil {
		t.Error(err)
	}

}

func TestHTTPGetterTarDownload(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f, _ := os.Open("testdata/empty-0.0.1.tgz")
		defer f.Close()

		b := make([]byte, 512)
		f.Read(b)
		//Get the file size
		FileStat, _ := f.Stat()
		FileSize := strconv.FormatInt(FileStat.Size(), 10)

		//Simulating improper header values from bitbucket
		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", FileSize)

		f.Seek(0, 0)
		io.Copy(w, f)
	}))

	defer srv.Close()

	g, err := NewHTTPGetter(WithURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}

	data, _ := g.Get(srv.URL)
	mimeType := http.DetectContentType(data.Bytes())

	expectedMimeType := "application/x-gzip"
	if mimeType != expectedMimeType {
		t.Fatalf("Expected response with MIME type %s, but got %s", expectedMimeType, mimeType)
	}
}

func TestHttpClientInsecureSkipVerify(t *testing.T) {
	g := HTTPGetter{}
	g.opts.url = "https://localhost"
	verifyInsecureSkipVerify(t, g, "Blank HTTPGetter", false)

	g = HTTPGetter{}
	g.opts.url = "https://localhost"
	g.opts.caFile = "testdata/ca.crt"
	verifyInsecureSkipVerify(t, g, "HTTPGetter with ca file", false)

	g = HTTPGetter{}
	g.opts.url = "https://localhost"
	g.opts.insecureSkipVerifyTLS = true
	verifyInsecureSkipVerify(t, g, "HTTPGetter with skip cert verification only", true)

	g = HTTPGetter{}
	g.opts.url = "https://localhost"
	g.opts.certFile = "testdata/client.crt"
	g.opts.keyFile = "testdata/client.key"
	g.opts.insecureSkipVerifyTLS = true
	transport := verifyInsecureSkipVerify(t, g, "HTTPGetter with 2 way ssl", true)
	if len(transport.TLSClientConfig.Certificates) <= 0 {
		t.Fatal("transport.TLSClientConfig.Certificates is not present")
	}
}

func verifyInsecureSkipVerify(t *testing.T, g HTTPGetter, caseName string, expectedValue bool) *http.Transport {
	returnVal, err := g.httpClient()

	if err != nil {
		t.Fatal(err)
	}

	if returnVal == nil {
		t.Fatalf("Expected non nil value for http client")
	}
	transport := (returnVal.Transport).(*http.Transport)
	gotValue := false
	if transport.TLSClientConfig != nil {
		gotValue = transport.TLSClientConfig.InsecureSkipVerify
	}
	if gotValue != expectedValue {
		t.Fatalf("Case Name = %s\nInsecureSkipVerify did not come as expected. Expected = %t; Got = %v",
			caseName, expectedValue, gotValue)
	}
	return transport
}

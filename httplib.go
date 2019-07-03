// Copyright 2019 Author. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package httplib is used as http.Client
// Usage:
//
// import "ringpool/httplib"
//
//	b := httplib.Post("http://beego.me/")
//	b.Param("username","astaxie")
//	b.Param("password","123456")
//	b.PostFile("uploadfile1", "httplib.pdf")
//	b.PostFile("uploadfile2", "httplib.txt")
//	str, err := b.String()
//	if err != nil {
//		t.Fatal(err)
//	}
//	fmt.Println(str)
//
//  more docs http://beego.me/docs/module/httplib.md
package httplib

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var defaultSetting = HTTPSettings{
	UserAgent:        "HTTP Go client",
	ConnectTimeout:   60 * time.Second,
	ReadWriteTimeout: 60 * time.Second,
	Gzip:             true,
	DumpBody:         true,
}

var defaultCookieJar http.CookieJar
var settingMutex sync.Mutex

// createDefaultCookie creates a global cookiejar to store cookies.
func createDefaultCookie() {
	settingMutex.Lock()
	defer settingMutex.Unlock()
	defaultCookieJar, _ = cookiejar.New(nil)
}

// SetDefaultSetting Overwrite default settings
func SetDefaultSetting(setting HTTPSettings) {
	settingMutex.Lock()
	defer settingMutex.Unlock()
	defaultSetting = setting
}

// NewBeegoRequest return *HTTPRequest with specific method
func NewBeegoRequest(rawurl, method string) *HTTPRequest {
	var resp http.Response
	u, err := url.Parse(rawurl)
	if err != nil {
		log.Println("Httplib:", err)
	}
	return &HTTPRequest{
		url: rawurl,
		req: &http.Request{
			URL:        u,
			Method:     method,
			Header:     make(http.Header),
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
		},
		params:  map[string][]string{},
		files:   map[string]string{},
		setting: defaultSetting,
		resp:    &resp,
	}
}

// Get returns *HTTPRequest with GET method.
func Get(url string) *HTTPRequest {
	return NewBeegoRequest(url, "GET")
}

// Post returns *HTTPRequest with POST method.
func Post(url string) *HTTPRequest {
	return NewBeegoRequest(url, "POST")
}

// Put returns *HTTPRequest with PUT method.
func Put(url string) *HTTPRequest {
	return NewBeegoRequest(url, "PUT")
}

// Delete returns *HTTPRequest DELETE method.
func Delete(url string) *HTTPRequest {
	return NewBeegoRequest(url, "DELETE")
}

// Head returns *HTTPRequest with HEAD method.
func Head(url string) *HTTPRequest {
	return NewBeegoRequest(url, "HEAD")
}

// HTTPSettings is the http.Client setting
type HTTPSettings struct {
	ShowDebug        bool
	UserAgent        string
	ConnectTimeout   time.Duration
	ReadWriteTimeout time.Duration
	TLSClientConfig  *tls.Config
	Proxy            func(*http.Request) (*url.URL, error)
	Transport        http.RoundTripper
	CheckRedirect    func(req *http.Request, via []*http.Request) error
	EnableCookie     bool
	Gzip             bool
	DumpBody         bool
	Retries          int // if set to -1 means will retry forever
}

// HTTPRequest provides more useful methods for requesting one url than http.Request.
type HTTPRequest struct {
	url     string
	req     *http.Request
	params  map[string][]string
	files   map[string]string
	setting HTTPSettings
	resp    *http.Response
	body    []byte
	dump    []byte
}

// GetRequest return the request object
func (r *HTTPRequest) GetRequest() *http.Request {
	return r.req
}

// Setting Change request settings
func (r *HTTPRequest) Setting(setting HTTPSettings) *HTTPRequest {
	r.setting = setting
	return r
}

// SetBasicAuth sets the request's Authorization header to use HTTP Basic Authentication with the provided username and password.
func (r *HTTPRequest) SetBasicAuth(username, password string) *HTTPRequest {
	r.req.SetBasicAuth(username, password)
	return r
}

// SetEnableCookie sets enable/disable cookiejar
func (r *HTTPRequest) SetEnableCookie(enable bool) *HTTPRequest {
	r.setting.EnableCookie = enable
	return r
}

// SetUserAgent sets User-Agent header field
func (r *HTTPRequest) SetUserAgent(useragent string) *HTTPRequest {
	r.setting.UserAgent = useragent
	return r
}

// Debug sets show debug or not when executing request.
func (r *HTTPRequest) Debug(isdebug bool) *HTTPRequest {
	r.setting.ShowDebug = isdebug
	return r
}

// Retries sets Retries times.
// default is 0 means no retried.
// -1 means retried forever.
// others means retried times.
func (r *HTTPRequest) Retries(times int) *HTTPRequest {
	r.setting.Retries = times
	return r
}

// DumpBody setting whether need to Dump the Body.
func (r *HTTPRequest) DumpBody(isdump bool) *HTTPRequest {
	r.setting.DumpBody = isdump
	return r
}

// DumpRequest return the DumpRequest
func (r *HTTPRequest) DumpRequest() []byte {
	return r.dump
}

// SetTimeout sets connect time out and read-write time out for BeegoRequest.
func (r *HTTPRequest) SetTimeout(connectTimeout, readWriteTimeout time.Duration) *HTTPRequest {
	r.setting.ConnectTimeout = connectTimeout
	r.setting.ReadWriteTimeout = readWriteTimeout
	return r
}

// SetTLSClientConfig sets tls connection configurations if visiting https url.
func (r *HTTPRequest) SetTLSClientConfig(config *tls.Config) *HTTPRequest {
	r.setting.TLSClientConfig = config
	return r
}

// Header add header item string in request.
func (r *HTTPRequest) Header(key, value string) *HTTPRequest {
	r.req.Header.Set(key, value)
	return r
}

// SetHost set the request host
func (r *HTTPRequest) SetHost(host string) *HTTPRequest {
	r.req.Host = host
	return r
}

// SetProtocolVersion Set the protocol version for incoming requests.
// Client requests always use HTTP/1.1.
func (r *HTTPRequest) SetProtocolVersion(vers string) *HTTPRequest {
	if len(vers) == 0 {
		vers = "HTTP/1.1"
	}

	major, minor, ok := http.ParseHTTPVersion(vers)
	if ok {
		r.req.Proto = vers
		r.req.ProtoMajor = major
		r.req.ProtoMinor = minor
	}

	return r
}

// SetCookie add cookie into request.
func (r *HTTPRequest) SetCookie(cookie *http.Cookie) *HTTPRequest {
	r.req.Header.Add("Cookie", cookie.String())
	return r
}

// SetTransport set the setting transport
func (r *HTTPRequest) SetTransport(transport http.RoundTripper) *HTTPRequest {
	r.setting.Transport = transport
	return r
}

// SetProxy set the http proxy
// example:
//
//	func(req *http.Request) (*url.URL, error) {
// 		u, _ := url.ParseRequestURI("http://127.0.0.1:8118")
// 		return u, nil
// 	}
func (r *HTTPRequest) SetProxy(proxy func(*http.Request) (*url.URL, error)) *HTTPRequest {
	r.setting.Proxy = proxy
	return r
}

// SetCheckRedirect specifies the policy for handling redirects.
//
// If CheckRedirect is nil, the Client uses its default policy,
// which is to stop after 10 consecutive requests.
func (r *HTTPRequest) SetCheckRedirect(redirect func(req *http.Request, via []*http.Request) error) *HTTPRequest {
	r.setting.CheckRedirect = redirect
	return r
}

// Param adds query param in to request.
// params build query string as ?key1=value1&key2=value2...
func (r *HTTPRequest) Param(key, value string) *HTTPRequest {
	if param, ok := r.params[key]; ok {
		r.params[key] = append(param, value)
	} else {
		r.params[key] = []string{value}
	}
	return r
}

// PostFile add a post file to the request
func (r *HTTPRequest) PostFile(formname, filename string) *HTTPRequest {
	r.files[formname] = filename
	return r
}

// Body adds request raw body.
// it supports string and []byte.
func (r *HTTPRequest) Body(data interface{}) *HTTPRequest {
	switch t := data.(type) {
	case string:
		bf := bytes.NewBufferString(t)
		r.req.Body = ioutil.NopCloser(bf)
		r.req.ContentLength = int64(len(t))
	case []byte:
		bf := bytes.NewBuffer(t)
		r.req.Body = ioutil.NopCloser(bf)
		r.req.ContentLength = int64(len(t))
	}
	return r
}

// XMLBody adds request raw body encoding by XML.
func (r *HTTPRequest) XMLBody(obj interface{}) (*HTTPRequest, error) {
	if r.req.Body == nil && obj != nil {
		byts, err := xml.Marshal(obj)
		if err != nil {
			return r, err
		}
		r.req.Body = ioutil.NopCloser(bytes.NewReader(byts))
		r.req.ContentLength = int64(len(byts))
		r.req.Header.Set("Content-Type", "application/xml")
	}
	return r, nil
}

// YAMLBody adds request raw body encoding by YAML.
func (r *HTTPRequest) YAMLBody(obj interface{}) (*HTTPRequest, error) {
	if r.req.Body == nil && obj != nil {
		byts, err := yaml.Marshal(obj)
		if err != nil {
			return r, err
		}
		r.req.Body = ioutil.NopCloser(bytes.NewReader(byts))
		r.req.ContentLength = int64(len(byts))
		r.req.Header.Set("Content-Type", "application/x+yaml")
	}
	return r, nil
}

// JSONBody adds request raw body encoding by JSON.
func (r *HTTPRequest) JSONBody(obj interface{}) (*HTTPRequest, error) {
	if r.req.Body == nil && obj != nil {
		byts, err := json.Marshal(obj)
		if err != nil {
			return r, err
		}
		r.req.Body = ioutil.NopCloser(bytes.NewReader(byts))
		r.req.ContentLength = int64(len(byts))
		r.req.Header.Set("Content-Type", "application/json")
	}
	return r, nil
}

func (r *HTTPRequest) buildURL(paramBody string) {
	// build GET url with query string
	if r.req.Method == "GET" && len(paramBody) > 0 {
		if strings.Contains(r.url, "?") {
			r.url += "&" + paramBody
		} else {
			r.url = r.url + "?" + paramBody
		}
		return
	}

	// build POST/PUT/PATCH url and body
	if (r.req.Method == "POST" || r.req.Method == "PUT" || r.req.Method == "PATCH" || r.req.Method == "DELETE") && r.req.Body == nil {
		// with files
		if len(r.files) > 0 {
			pr, pw := io.Pipe()
			bodyWriter := multipart.NewWriter(pw)
			go func() {
				for formname, filename := range r.files {
					fileWriter, err := bodyWriter.CreateFormFile(formname, filename)
					if err != nil {
						log.Println("Httplib:", err)
					}
					fh, err := os.Open(filename)
					if err != nil {
						log.Println("Httplib:", err)
					}
					//iocopy
					_, err = io.Copy(fileWriter, fh)
					fh.Close()
					if err != nil {
						log.Println("Httplib:", err)
					}
				}
				for k, v := range r.params {
					for _, vv := range v {
						bodyWriter.WriteField(k, vv)
					}
				}
				bodyWriter.Close()
				pw.Close()
			}()
			r.Header("Content-Type", bodyWriter.FormDataContentType())
			r.req.Body = ioutil.NopCloser(pr)
			return
		}

		// with params
		if len(paramBody) > 0 {
			r.Header("Content-Type", "application/x-www-form-urlencoded")
			r.Body(paramBody)
		}
	}
}

func (r *HTTPRequest) getResponse() (*http.Response, error) {
	if r.resp.StatusCode != 0 {
		return r.resp, nil
	}
	resp, err := r.DoRequest()
	if err != nil {
		return nil, err
	}
	r.resp = resp
	return resp, nil
}

// DoRequest will do the client.Do
func (r *HTTPRequest) DoRequest() (resp *http.Response, err error) {
	var paramBody string
	if len(r.params) > 0 {
		var buf bytes.Buffer
		for k, v := range r.params {
			for _, vv := range v {
				buf.WriteString(url.QueryEscape(k))
				buf.WriteByte('=')
				buf.WriteString(url.QueryEscape(vv))
				buf.WriteByte('&')
			}
		}
		paramBody = buf.String()
		paramBody = paramBody[0 : len(paramBody)-1]
	}

	r.buildURL(paramBody)
	urlParsed, err := url.Parse(r.url)
	if err != nil {
		return nil, err
	}

	r.req.URL = urlParsed

	trans := r.setting.Transport

	if trans == nil {
		// create default transport
		trans = &http.Transport{
			TLSClientConfig:     r.setting.TLSClientConfig,
			Proxy:               r.setting.Proxy,
			Dial:                TimeoutDialer(r.setting.ConnectTimeout, r.setting.ReadWriteTimeout),
			MaxIdleConnsPerHost: 100,
		}
	} else {
		// if b.transport is *http.Transport then set the settings.
		if t, ok := trans.(*http.Transport); ok {
			if t.TLSClientConfig == nil {
				t.TLSClientConfig = r.setting.TLSClientConfig
			}
			if t.Proxy == nil {
				t.Proxy = r.setting.Proxy
			}
			if t.Dial == nil {
				t.Dial = TimeoutDialer(r.setting.ConnectTimeout, r.setting.ReadWriteTimeout)
			}
		}
	}

	var jar http.CookieJar
	if r.setting.EnableCookie {
		if defaultCookieJar == nil {
			createDefaultCookie()
		}
		jar = defaultCookieJar
	}

	client := &http.Client{
		Transport: trans,
		Jar:       jar,
	}

	if r.setting.UserAgent != "" && r.req.Header.Get("User-Agent") == "" {
		r.req.Header.Set("User-Agent", r.setting.UserAgent)
	}

	if r.setting.CheckRedirect != nil {
		client.CheckRedirect = r.setting.CheckRedirect
	}

	if r.setting.ShowDebug {
		dump, err := httputil.DumpRequest(r.req, r.setting.DumpBody)
		if err != nil {
			log.Println(err.Error())
		}
		r.dump = dump
	}
	// retries default value is 0, it will run once.
	// retries equal to -1, it will run forever until success
	// retries is setted, it will retries fixed times.
	for i := 0; r.setting.Retries == -1 || i <= r.setting.Retries; i++ {
		resp, err = client.Do(r.req)
		if err == nil {
			break
		}
	}
	return resp, err
}

// String returns the body string in response.
// it calls Response inner.
func (r *HTTPRequest) String() (string, error) {
	data, err := r.Bytes()
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Bytes returns the body []byte in response.
// it calls Response inner.
func (r *HTTPRequest) Bytes() ([]byte, error) {
	if r.body != nil {
		return r.body, nil
	}
	resp, err := r.getResponse()
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return nil, nil
	}
	defer resp.Body.Close()
	if r.setting.Gzip && resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		r.body, err = ioutil.ReadAll(reader)
		return r.body, err
	}
	r.body, err = ioutil.ReadAll(resp.Body)
	return r.body, err
}

// ToFile saves the body data in response to one file.
// it calls Response inner.
func (r *HTTPRequest) ToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	resp, err := r.getResponse()
	if err != nil {
		return err
	}
	if resp.Body == nil {
		return nil
	}
	defer resp.Body.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

// ToJSON returns the map that marshals from the body bytes as json in response .
// it calls Response inner.
func (r *HTTPRequest) ToJSON(v interface{}) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// ToXML returns the map that marshals from the body bytes as xml in response .
// it calls Response inner.
func (r *HTTPRequest) ToXML(v interface{}) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(data, v)
}

// ToYAML returns the map that marshals from the body bytes as yaml in response .
// it calls Response inner.
func (r *HTTPRequest) ToYAML(v interface{}) error {
	data, err := r.Bytes()
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, v)
}

// Response executes request client gets response mannually.
func (r *HTTPRequest) Response() (*http.Response, error) {
	return r.getResponse()
}

// TimeoutDialer returns functions of connection dialer with timeout settings for http.Transport Dial field.
func TimeoutDialer(cTimeout time.Duration, rwTimeout time.Duration) func(net, addr string) (c net.Conn, err error) {
	return func(netw, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(netw, addr, cTimeout)
		if err != nil {
			return nil, err
		}
		err = conn.SetDeadline(time.Now().Add(rwTimeout))
		return conn, err
	}
}

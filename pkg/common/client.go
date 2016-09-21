/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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

package common

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/layer3/routers"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/extensions/portsbinding"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/networks"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/subnets"
	"github.com/gophercloud/gophercloud/pagination"
)

type OpenDaylightClient struct {
	BaseUrl string

	// HTTPClient allows users to interject arbitrary http, https, or other transit behaviors.
	HTTPClient http.Client
}

func NewOpenDaylightClient(config *Config) (OpenDaylightClient, error) {
	return OpenDaylightClient{
		BaseUrl:    config.Global.Url,
		HTTPClient: *http.DefaultClient,
	}, nil

}

// RequestOpts customizes the behavior of the provider.Request() method.
type RequestOpts struct {
	// JSONBody, if provided, will be encoded as JSON and used as the body of the HTTP request. The
	// content type of the request will default to "application/json" unless overridden by MoreHeaders.
	// It's an error to specify both a JSONBody and a RawBody.
	JSONBody interface{}
	// RawBody contains an io.Reader that will be consumed by the request directly. No content-type
	// will be set unless one is provided explicitly by MoreHeaders.
	RawBody io.Reader
	// JSONResponse, if provided, will be populated with the contents of the response body parsed as
	// JSON.
	JSONResponse interface{}
	// OkCodes contains a list of numeric HTTP status codes that should be interpreted as success. If
	// the response has a different code, an error will be returned.
	OkCodes []int
	// MoreHeaders specifies additional HTTP headers to be provide on the request. If a header is
	// provided with a blank value (""), that header will be *omitted* instead: use this to suppress
	// the default Accept header or an inferred Content-Type, for example.
	MoreHeaders map[string]string
	// ErrorContext specifies the resource error type to return if an error is encountered.
	// This lets resources override default error messages based on the response status code.
	ErrorContext error
}

var applicationJSON = "application/json"

// Request performs an HTTP request using the ProviderClient's current HTTPClient. An authentication
// header will automatically be provided.
func (client *OpenDaylightClient) Request(method, url string, options *RequestOpts) (*http.Response, error) {
	var body io.Reader
	var contentType *string

	// Derive the content body by either encoding an arbitrary object as JSON, or by taking a provided
	// io.ReadSeeker as-is. Default the content-type to application/json.
	if options.JSONBody != nil {
		if options.RawBody != nil {
			panic("Please provide only one of JSONBody or RawBody to gophercloud.Request().")
		}

		rendered, err := json.Marshal(options.JSONBody)
		if err != nil {
			return nil, err
		}

		body = bytes.NewReader(rendered)
		contentType = &applicationJSON
	}

	if options.RawBody != nil {
		body = options.RawBody
	}

	// Construct the http.Request.
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	// Populate the request headers. Apply options.MoreHeaders last, to give the caller the chance to
	// modify or omit any header.
	if contentType != nil {
		req.Header.Set("Content-Type", *contentType)
	}
	req.Header.Set("Accept", applicationJSON)

	// Set connection parameter to close the connection immediately when we've got the response
	req.Close = true

	// Issue the request.
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Allow default OkCodes if none explicitly set
	if options.OkCodes == nil {
		options.OkCodes = defaultOkCodes(method)
	}

	// Validate the HTTP response status.
	var ok bool
	for _, code := range options.OkCodes {
		if resp.StatusCode == code {
			ok = true
			break
		}
	}

	if !ok {
		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		respErr := ErrUnexpectedResponseCode{
			URL:      url,
			Method:   method,
			Expected: options.OkCodes,
			Actual:   resp.StatusCode,
			Body:     body,
		}
		//respErr.Function = "gophercloud.ProviderClient.Request"

		errType := options.ErrorContext
		switch resp.StatusCode {
		case http.StatusBadRequest:
			err = ErrDefault400{respErr}
			if error400er, ok := errType.(Err400er); ok {
				err = error400er.Error400(respErr)
			}
		case http.StatusUnauthorized:
			if client.ReauthFunc != nil {
				err = client.ReauthFunc()
				if err != nil {
					e := &ErrUnableToReauthenticate{}
					e.ErrOriginal = respErr
					return nil, e
				}
				if options.RawBody != nil {
					if seeker, ok := options.RawBody.(io.Seeker); ok {
						seeker.Seek(0, 0)
					}
				}
				resp, err = client.Request(method, url, options)
				if err != nil {
					switch err.(type) {
					case *ErrUnexpectedResponseCode:
						e := &ErrErrorAfterReauthentication{}
						e.ErrOriginal = err.(*ErrUnexpectedResponseCode)
						return nil, e
					default:
						e := &ErrErrorAfterReauthentication{}
						e.ErrOriginal = err
						return nil, e
					}
				}
				return resp, nil
			}
			err = ErrDefault401{respErr}
			if error401er, ok := errType.(Err401er); ok {
				err = error401er.Error401(respErr)
			}
		case http.StatusNotFound:
			err = ErrDefault404{respErr}
			if error404er, ok := errType.(Err404er); ok {
				err = error404er.Error404(respErr)
			}
		case http.StatusMethodNotAllowed:
			err = ErrDefault405{respErr}
			if error405er, ok := errType.(Err405er); ok {
				err = error405er.Error405(respErr)
			}
		case http.StatusRequestTimeout:
			err = ErrDefault408{respErr}
			if error408er, ok := errType.(Err408er); ok {
				err = error408er.Error408(respErr)
			}
		case 429:
			err = ErrDefault429{respErr}
			if error429er, ok := errType.(Err429er); ok {
				err = error429er.Error429(respErr)
			}
		case http.StatusInternalServerError:
			err = ErrDefault500{respErr}
			if error500er, ok := errType.(Err500er); ok {
				err = error500er.Error500(respErr)
			}
		case http.StatusServiceUnavailable:
			err = ErrDefault503{respErr}
			if error503er, ok := errType.(Err503er); ok {
				err = error503er.Error503(respErr)
			}
		}

		if err == nil {
			err = respErr
		}

		return resp, err
	}

	// Parse the response body as JSON, if requested to do so.
	if options.JSONResponse != nil {
		defer resp.Body.Close()
		if err := json.NewDecoder(resp.Body).Decode(options.JSONResponse); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func defaultOkCodes(method string) []int {
	switch {
	case method == "GET":
		return []int{200}
	case method == "POST":
		return []int{201, 202}
	case method == "PUT":
		return []int{201, 202}
	case method == "PATCH":
		return []int{200, 204}
	case method == "DELETE":
		return []int{202, 204}
	}

	return []int{}
}

// Get calls `Request` with the "GET" HTTP verb.
func (client *OpenDaylightClient) Get(url string, JSONResponse interface{}, opts *RequestOpts) (*http.Response, error) {
	if opts == nil {
		opts = &RequestOpts{}
	}
	if JSONResponse != nil {
		opts.JSONResponse = JSONResponse
	}

	if opts.MoreHeaders == nil {
		opts.MoreHeaders = make(map[string]string)
	}

	return client.Request("GET", url, opts)
}

// Post calls `Request` with the "POST" HTTP verb.
func (client *OpenDaylightClient) Post(url string, JSONBody interface{}, JSONResponse interface{}, opts *RequestOpts) (*http.Response, error) {
	if opts == nil {
		opts = &RequestOpts{}
	}

	if v, ok := (JSONBody).(io.Reader); ok {
		opts.RawBody = v
	} else if JSONBody != nil {
		opts.JSONBody = JSONBody
	}

	if JSONResponse != nil {
		opts.JSONResponse = JSONResponse
	}

	if opts.MoreHeaders == nil {
		opts.MoreHeaders = make(map[string]string)
	}

	return client.Request("POST", url, opts)
}

// Put calls `Request` with the "PUT" HTTP verb.
func (client *OpenDaylightClient) Put(url string, JSONBody interface{}, JSONResponse interface{}, opts *RequestOpts) (*http.Response, error) {
	if opts == nil {
		opts = &RequestOpts{}
	}

	if v, ok := (JSONBody).(io.Reader); ok {
		opts.RawBody = v
	} else if JSONBody != nil {
		opts.JSONBody = JSONBody
	}

	if JSONResponse != nil {
		opts.JSONResponse = JSONResponse
	}

	if opts.MoreHeaders == nil {
		opts.MoreHeaders = make(map[string]string)
	}

	return client.Request("PUT", url, opts)
}

// Patch calls `Request` with the "PATCH" HTTP verb.
func (client *OpenDaylightClient) Patch(url string, JSONBody interface{}, JSONResponse interface{}, opts *RequestOpts) (*http.Response, error) {
	if opts == nil {
		opts = &RequestOpts{}
	}

	if v, ok := (JSONBody).(io.Reader); ok {
		opts.RawBody = v
	} else if JSONBody != nil {
		opts.JSONBody = JSONBody
	}

	if JSONResponse != nil {
		opts.JSONResponse = JSONResponse
	}

	if opts.MoreHeaders == nil {
		opts.MoreHeaders = make(map[string]string)
	}

	return client.Request("PATCH", url, opts)
}

// Delete calls `Request` with the "DELETE" HTTP verb.
func (client *OpenDaylightClient) Delete(url string, opts *RequestOpts) (*http.Response, error) {
	if opts == nil {
		opts = &RequestOpts{}
	}

	if opts.MoreHeaders == nil {
		opts.MoreHeaders = make(map[string]string)
	}

	return client.Request("DELETE", url, opts)
}

// network
func (client *OpenDaylightClient) CreateNetwork(opts networks.CreateOpts) (r networks.CreateResult) {
	url := client.BaseUrl + "/v2.0/networks"
	b, err := opts.ToNetworkCreateMap()
	if err != nil {
		r.Err = err
		return
	}
	_, r.Err = client.Post(url, b, &r.Body, nil)
	return
}

func (client *OpenDaylightClient) DeleteNetwork(networkId string) (r networks.DeleteResult) {
	url := client.BaseUrl + "/v2.0/network/" + networkId
	_, r.Err = client.Delete(deleteURL(c, networkID), nil)
	return
}

func (client *OpenDaylightClient) ListNetwork(opts *networks.ListOpts) pagination.Pager {
	url := client.BaseUrl + "/v2.0/networks/"
	if opts != nil {
		query, err := opts.ToNetworkListQuery()
		if err != nil {
			return pagination.Pager{Err: err}
		}
		url += query
	}
	return pagination.NewPager(client, url, func(r pagination.PageResult) pagination.Page {
		return NetworkPage{pagination.LinkedPageBase{PageResult: r}}
	})
}

//TODO: update network
func (client *OpenDaylightClient) UpdateNetwork() {

}

// subnet

func (client *OpenDaylightClient) CreateSubnet(opts subnets.CreateOpts) (r subnets.CreateResult) {
	url := client.BaseUrl + "/v2.0/subnet"
	b, err := opts.ToSubnetCreateMap()
	if err != nil {
		r.Err = err
		return
	}
	_, r.Err = client.Post(url, b, &r.Body, nil)
	return
}

func (client *OpenDaylightClient) DeleteSubnet(subnetId string) (r subnets.DeleteResult) {
	url := client.BaseUrl + "/v2.0/subnet/" + subnetId
	_, r.Err = client.Delete(url, nil)
	return
}

func (client *OpenDaylightClient) GetSubnet(subnetId string) (r subnets.GetResult) {
	url := client.BaseUrl + "/v2.0/subnet/" + subnetId
	_, r.Err = client.Get(url, &r.Body, nil)
	return
}

// port
func (client *OpenDaylightClient) CreatePort(opts portsbinding.CreateOpts) (r portsbinding.CreateResult) {
	url := client.BaseUrl + "/v2.0/ports"
	b, err := opts.ToPortCreateMap()
	if err != nil {
		r.Err = err
		return
	}
	_, r.Err = client.Post(url, b, &r.Body, nil)
	return
}

func (client *OpenDaylightClient) DeletePort(portId string) (r ports.DeleteResult) {
	url := client.BaseUrl + "/v2.0/ports" + portId
	_, r.Err = client.Delete(url, nil)
	return
}

func (client *OpenDaylightClient) ListPort(opts ports.ListOpts) pagination.Pager {
	url := client.BaseUrl + "/v2.0/ports/"
	if opts != nil {
		query, err := opts.ToPortListQuery()
		if err != nil {
			return pagination.Pager{Err: err}
		}
		url += query
	}
	return pagination.NewPager(client, url, func(r pagination.PageResult) pagination.Pager {
		return PortPage{pagination.LinkedPageBase{PageResult: r}}
	})
}

func (client *OpenDaylightClient) UpdatePort(portId string, opts portsbinding.UpdateOpts) (r portsbinding.UpdateResult) {
	url := client.BaseUrl + "/v2.0/port/" + portId
	b, err := opts.ToPortUpdateMap()
	if err != nil {
		r.Err = err
		return r
	}
	_, r.Err = client.Put(url, b, &r.Body, &gophercloud.RequestOpts{
		OkCodes: []int{200, 201},
	})
	return
}

//router
func (client *OpenDaylightClient) CreateRouter(opts routers.CreateOpts) (r routers.CreateResult) {
	url := client.BaseUrl + "/v2.0/routers"
	b, err := opts.ToRouterCreateMap()
	if err != nil {
		r.Err = err
		return
	}
	_, r.Err = client.Post(rootURL(c), b, &r.Body, nil)
	return
}

func (client *OpenDaylightClient) DeleteRouter(routerId string) (r routers.DeleteResult) {
	url := client.BaseUrl + "/v2.0/routers/" + routerId
	_, r.Err = client.Delete(url, nil)
	return
}

func (client *OpenDaylightClient) ListRouter(opts routers.ListOpts) pagination.Pager {
	url := client.BaseUrl + "/v2.0/routers/"
	q, err := gophercloud.BuildQueryString(&opts)
	if err != nil {
		return pagination.Pager{Err: err}
	}
	u := url + q.String()
	return pagination.NewPager(client, u, func(r pagination.PageResult) pagination.Page {
		return RouterPage{pagination.LinkedPageBase{PageResult: r}}
	})
}

func (client *OpenDaylightClient) UpdateRouter() {
	//TODO: update router
}

// interface
func (client *OpenDaylightClient) AddInterface(routerId string, opts routers.AddInterfaceOpts) (r routers.InterfaceResult) {
	url := client.BaseUrl + "/v2.0/routers/" + routerId
	b, err := opts.ToRouterAddInterfaceMap()
	if err != nil {
		r.Err = err
		return
	}
	_, r.Err = client.Put(url, b, &r.Body, &gophercloud.RequestOpts{
		OkCodes: []int{200},
	})
	return
}

func (client *OpenDaylightClient) RemoveInterface(routerId string, opts routers.RemoveInterfaceOpts) (r routers.InterfaceResult) {
	url := client.BaseUrl + "/v2.0/routers/" + routerId
	b, err := opts.ToRouterRemoveInterfaceMap()
	if err != nil {
		r.Err = err
		return
	}
	_, r.Err = client.Put(url, b, &r.Body, &gophercloud.RequestOpts{
		OkCodes: []int{200},
	})
	return
}

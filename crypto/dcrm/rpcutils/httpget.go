package rpcutils

import (
	"io/ioutil"
	"net/http"
	neturl "net/url"
	"strings"
)

func HttpGet(host string, path string, params map[string][]string) ([]byte, error) {
	host = strings.Replace(host, "http://", "", -1)
	host = strings.Trim(host, "/")
	path = strings.Trim(path, "/")
	url := neturl.URL{
		Scheme: "http",
		Host: host,
		Path: path,
	}
	requrl := url.String()
	values := neturl.Values(params)
	if params != nil {
		requrl = requrl+"?"+values.Encode()
	}
	resp, err := http.Get(requrl)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	return body, err
}


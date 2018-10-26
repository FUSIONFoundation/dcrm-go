/*******************@ https://www.cnblogs.com/hotion/p/9644167.html***************************/

// Copyright 2018 The fusion-dcrm 
//Author: caihaijun@fusion.org

package dcrm

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
	//"log"
)

const (
	VERSION           = 0.1
	RPCCLIENT_TIMEOUT = 30
	
	SERVER_HOST        = "localhost"
	SERVER_PORT        = 18443 
	USER               = "xxmm"
	PASSWD             = "123456"
	USESSL             = false
	WALLET_PASSPHRASE  = "WalletPassphrase"
)

/*func main() {
	test02()

}

func test02(){
	rpcClient, err := NewClient(SERVER_HOST, SERVER_PORT, USER, PASSWD, USESSL)
	if err != nil {
		log.Fatalln(err)
	}
	//生成一个新地址
	reqJson := "{\"method\":\"getnewaddress\",\"params\":[\"labelName002\"],\"id\":1}";
	returnJson, err2 := rpcClient.Send(reqJson)
	if err2 != nil {
		log.Fatalln(err2)
	}
	log.Println("returnJson:", returnJson)
}
*/

// 钱包连接参数
type rpcClient struct {
	serverAddr string
	user       string
	passwd     string
	httpClient *http.Client
}

// 请求信息
type rpcRequest struct {
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
	Id      int64       `json:"id"`
	JsonRpc string      `json:"jsonrpc"`
}

type rpcResponse struct {
	Id     int64           `json:"id"`
	Result json.RawMessage `json:"result"`
	Err    interface{}     `json:"error"`
}

//连接配置
func NewClient(host string, port int, user, passwd string, useSSL bool) (c *rpcClient, err error) {
	if len(host) == 0 {
		err = errors.New("Bad call missing argument host")
		return
	}
	var serverAddr string
	var httpClient *http.Client
	if useSSL {
		serverAddr = "https://"
		t := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		httpClient = &http.Client{Transport: t}
	} else {
		serverAddr = "http://"
		httpClient = &http.Client{}
	}
	c = &rpcClient{serverAddr: fmt.Sprintf("%s%s:%d", serverAddr, host, port), user: user, passwd: passwd, httpClient: httpClient}
	return
}

// 超时处理
func (c *rpcClient) doTimeoutRequest(timer *time.Timer, req *http.Request) (*http.Response, error) {
	type result struct {
		resp *http.Response
		err  error
	}
	done := make(chan result, 1)
	go func() {
		resp, err := c.httpClient.Do(req)
		done <- result{resp, err}
	}()
	// Wait for the read or the timeout
	select {
	case r := <-done:
		return r.resp, r.err
	case <-timer.C:
		return nil, errors.New("Timeout reading data from server")
	}
}

//通信
func (c *rpcClient) Send(reqJson string) (retJSON string, err error) {
	connectTimer := time.NewTimer(RPCCLIENT_TIMEOUT * time.Second)
	reqJsonByte := []byte(reqJson)
	payloadBuffer := bytes.NewReader(reqJsonByte)
	req, err := http.NewRequest("POST", c.serverAddr, payloadBuffer)
	if err != nil {
		return
	}
	req.Header.Add("Content-Type", "application/json;charset=utf-8")
	req.Header.Add("Accept", "application/json")
	if len(c.user) > 0 || len(c.passwd) > 0 {
		req.SetBasicAuth(c.user, c.passwd)
	}
	resp, err := c.doTimeoutRequest(connectTimer, req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = errors.New("HTTP error: " + resp.Status)
		return
	}
	retJSON = string(data)
	return
}

package rpcutils
import (
	"bytes"
	"log"
	"os/exec"

	"io/ioutil"
	"net/http"
)

func DoCurlRequest (url, api, data string) string {
	var err error
	cmd := exec.Command("/bin/sh")
	in := bytes.NewBuffer(nil)
	cmd.Stdin = in
	var out bytes.Buffer
	cmd.Stdout = &out
	go func() {
		str := "curl -X POST " + url + "/" + api
		if len(data) > 0 {
			str = str + " -d " + "'" + data + "'"
		}
		in.WriteString(str)
	}()
	err = cmd.Start()
	if err != nil {
		log.Fatal(err)
	}
	log.Println(cmd.Args)
	err = cmd.Wait()
	if err != nil {
		log.Printf("Command finished with error: %v", err)
	}
	return out.String()
}

func DoPostRequest (url, api, reqData string) string {
	req := bytes.NewBuffer([]byte(reqData))
log.Println(url + "/" + api, "application/json;charset=utf-8")
log.Println(reqData)
	resp, _ := http.Post(url + "/" + api, "application/json;charset=utf-8", req)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body)
}

func DoPostRequest2 (url, reqData string) string {
	req := bytes.NewBuffer([]byte(reqData))
	resp, _ := http.Post(url, "application/json;charset=utf-8", req)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body)
}


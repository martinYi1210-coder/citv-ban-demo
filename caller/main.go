package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

type BanRequest struct {
	Ccid    string `json:"ccid"`
	Casn    string `json:"casn"`
	Action  int    `json:"action"`
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

type BanResponse struct {
	TicketId  string `json:"ticketId"`
	Ccid      string `json:"ccid"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	Sign      string `json:"sign"`
}

type ErrorResponse struct {
	Isok   bool        `json:"isok"`
	Msg    string      `json:"msg"`
	Code   int         `json:"code"`
	DataObj interface{} `json:"dataObj"`
}

var (
	citvPrivateKey *rsa.PrivateKey
	saasPublicKey   *rsa.PublicKey
)

func loadKeys() {
	privData, err := os.ReadFile("../keys/citv_private.pem")
	if err != nil {
		fmt.Println("读取CITV私钥失败:", err)
		os.Exit(1)
	}
	privBlock, _ := pem.Decode(privData)
	citvPrivateKey, err = x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		fmt.Println("解析CITV私钥失败:", err)
		os.Exit(1)
	}

	pubData, err := os.ReadFile("../keys/saas_public.pem")
	if err != nil {
		fmt.Println("读取SaaS公钥失败:", err)
		os.Exit(1)
	}
	pubBlock, _ := pem.Decode(pubData)
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		fmt.Println("解析SaaS公钥失败:", err)
		os.Exit(1)
	}
	saasPublicKey = pub.(*rsa.PublicKey)
}

func generateSign(params map[string]string, privKey *rsa.PrivateKey) (string, error) {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	signStr := ""
	for _, k := range keys {
		if signStr != "" {
			signStr += "&"
		}
		signStr += fmt.Sprintf("%s=%s", k, params[k])
	}

	hash := sha256.New()
	hash.Write([]byte(signStr))
	hashed := hash.Sum(nil)

	signBytes, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signBytes), nil
}

func verifySign(sign string, params map[string]string, pubKey *rsa.PublicKey) bool {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	signStr := ""
	for _, k := range keys {
		if signStr != "" {
			signStr += "&"
		}
		signStr += fmt.Sprintf("%s=%s", k, params[k])
	}

	hash := sha256.New()
	hash.Write([]byte(signStr))
	hashed := hash.Sum(nil)

	signBytes, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return false
	}

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed, signBytes)
	return err == nil
}

func sendBanRequest(req BanRequest) (*BanResponse, error) {
	appid := "test-appid-123"
	nonce := fmt.Sprintf("nonce-%d", time.Now().UnixNano())
	timestamp := time.Now().UnixMilli()

	signParams := map[string]string{
		"appid":     appid,
		"casn":      req.Casn,
		"ccid":      req.Ccid,
		"nonce":     nonce,
		"timestamp": strconv.FormatInt(timestamp, 10),
	}

	sign, err := generateSign(signParams, citvPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("生成签名失败: %v", err)
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("序列化请求失败: %v", err)
	}

	httpReq, err := http.NewRequest("POST", "http://localhost:8081/ban/v2", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("sign", sign)
	httpReq.Header.Set("timestamp", strconv.FormatInt(timestamp, 10))
	httpReq.Header.Set("nonce", nonce)
	httpReq.Header.Set("appid", appid)

	fmt.Printf("发送请求: sign=%s...\n", sign[:30])
	fmt.Printf("请求体: %s\n", string(body))

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("发送请求失败: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	fmt.Printf("响应状态: %d\n", resp.StatusCode)
	fmt.Printf("响应体: %s\n", string(respBody))

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("请求失败: %s", string(respBody))
	}

	var banResp BanResponse
	if err := json.Unmarshal(respBody, &banResp); err != nil {
		var errResp ErrorResponse
		if json.Unmarshal(respBody, &errResp) == nil {
			return nil, fmt.Errorf("接口错误: code=%d, msg=%s", errResp.Code, errResp.Msg)
		}
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	verifyParams := map[string]string{
		"ccid":      banResp.Ccid,
		"nonce":     banResp.Nonce,
		"ticketId":  banResp.TicketId,
		"timestamp": strconv.FormatInt(banResp.Timestamp, 10),
	}

	if verifySign(banResp.Sign, verifyParams, saasPublicKey) {
		fmt.Println("响应签名验证成功")
	} else {
		fmt.Println("响应签名验证失败")
	}

	return &banResp, nil
}

func main() {
	loadKeys()
	fmt.Println("调用方(CITV)启动成功")
	fmt.Println("测试citv-callback-v2 封禁接口")
	fmt.Println("==============================")

	testCases := []BanRequest{
		{
			Ccid:    "CCID-TEST-001",
			Casn:    "CASN-2024-0001",
			Action:  -1,
			Code:    0,
			Message: "测试封禁",
		},
		{
			Ccid:    "CCID-TEST-002",
			Casn:    "CASN-2024-0002",
			Action:  24,
			Code:    1,
			Message: "涉黄内容整改",
		},
		{
			Ccid:    "CCID-TEST-003",
			Casn:    "CASN-2024-0003",
			Action:  127,
			Code:    100,
			Message: "解除封禁",
		},
	}

	for i, tc := range testCases {
		fmt.Printf("\n测试用例 %d:\n", i+1)
		fmt.Println("------------------")
		resp, err := sendBanRequest(tc)
		if err != nil {
			fmt.Printf("请求失败: %v\n", err)
		} else {
			fmt.Printf("处理成功, ticketId=%s\n", resp.TicketId)
		}
		time.Sleep(1 * time.Second)
	}
}

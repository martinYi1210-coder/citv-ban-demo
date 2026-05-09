package main

import (
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
	"sync"
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
	citvPublicKey *rsa.PublicKey
	saasPrivateKey *rsa.PrivateKey
	nonceStore     = make(map[string]time.Time)
	nonceMutex     sync.RWMutex
)

func loadKeys() {
	// 加载CITV公钥（用于验证请求签名）
	pubData, err := os.ReadFile("../keys/citv_public.pem")
	if err != nil {
		fmt.Println("读取CITV公钥失败:", err)
		os.Exit(1)
	}
	pubBlock, _ := pem.Decode(pubData)
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		fmt.Println("解析CITV公钥失败:", err)
		os.Exit(1)
	}
	citvPublicKey = pub.(*rsa.PublicKey)

	// 加载SaaS私钥（用于生成响应签名）
	privData, err := os.ReadFile("../keys/saas_private.pem")
	if err != nil {
		fmt.Println("读取SaaS私钥失败:", err)
		os.Exit(1)
	}
	privBlock, _ := pem.Decode(privData)
	saasPrivateKey, err = x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		fmt.Println("解析SaaS私钥失败:", err)
		os.Exit(1)
	}
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

func isNonceUnique(nonce string) bool {
	nonceMutex.RLock()
	_, exists := nonceStore[nonce]
	nonceMutex.RUnlock()
	if exists {
		return false
	}

	nonceMutex.Lock()
	nonceStore[nonce] = time.Now()
	nonceMutex.Unlock()

	go func() {
		time.Sleep(10 * time.Minute)
		nonceMutex.Lock()
		delete(nonceStore, nonce)
		nonceMutex.Unlock()
	}()

	return true
}

func banHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	sign := r.Header.Get("sign")
	timestamp := r.Header.Get("timestamp")
	nonce := r.Header.Get("nonce")
	appid := r.Header.Get("appid")

	if sign == "" {
		json.NewEncoder(w).Encode(ErrorResponse{Isok: false, Msg: "签名为空", Code: -100, DataObj: nil})
		return
	}
	if timestamp == "" {
		json.NewEncoder(w).Encode(ErrorResponse{Isok: false, Msg: "时间戳为空", Code: -101, DataObj: nil})
		return
	}
	if appid == "" {
		json.NewEncoder(w).Encode(ErrorResponse{Isok: false, Msg: "AppId为空", Code: -102, DataObj: nil})
		return
	}
	if appid != "test-appid-123" {
		json.NewEncoder(w).Encode(ErrorResponse{Isok: false, Msg: "AppId非法", Code: -104, DataObj: nil})
		return
	}

	ts, _ := strconv.ParseInt(timestamp, 10, 64)
	now := time.Now().UnixMilli()
	if now-ts > 5*60*1000 || ts-now > 5*60*1000 {
		json.NewEncoder(w).Encode(ErrorResponse{Isok: false, Msg: "时间戳过期", Code: -103, DataObj: nil})
		return
	}

	if !isNonceUnique(nonce) {
		json.NewEncoder(w).Encode(ErrorResponse{Isok: false, Msg: "nonce重复", Code: -103, DataObj: nil})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		json.NewEncoder(w).Encode(ErrorResponse{Isok: false, Msg: "读取请求体失败", Code: -1, DataObj: nil})
		return
	}

	var req BanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		json.NewEncoder(w).Encode(ErrorResponse{Isok: false, Msg: "解析请求体失败", Code: -1, DataObj: nil})
		return
	}

	verifyParams := map[string]string{
		"appid":     appid,
		"casn":      req.Casn,
		"ccid":      req.Ccid,
		"nonce":     nonce,
		"timestamp": timestamp,
	}

	if !verifySign(sign, verifyParams, citvPublicKey) {
		json.NewEncoder(w).Encode(ErrorResponse{Isok: false, Msg: "签名验证失败", Code: -103, DataObj: nil})
		return
	}

	fmt.Printf("收到封禁请求: ccid=%s, casn=%s, action=%d, code=%d, message=%s\n",
		req.Ccid, req.Casn, req.Action, req.Code, req.Message)

	ticketId := fmt.Sprintf("TICKET-%d", time.Now().Unix())
	respNonce := fmt.Sprintf("resp-%d", time.Now().UnixNano())
	respTs := time.Now().UnixMilli()

	respSignParams := map[string]string{
		"ccid":      req.Ccid,
		"nonce":     respNonce,
		"ticketId":  ticketId,
		"timestamp": strconv.FormatInt(respTs, 10),
	}

	respSign, err := generateSign(respSignParams, saasPrivateKey)
	if err != nil {
		json.NewEncoder(w).Encode(ErrorResponse{Isok: false, Msg: "生成响应签名失败", Code: -1, DataObj: nil})
		return
	}

	resp := BanResponse{
		TicketId:  ticketId,
		Ccid:      req.Ccid,
		Nonce:     respNonce,
		Timestamp: respTs,
		Sign:      respSign,
	}

	fmt.Printf("返回响应: %+v\n", resp)
	json.NewEncoder(w).Encode(resp)
}

func main() {
	loadKeys()
	fmt.Println("被调用方(SaaS平台)启动成功")
	fmt.Println("监听端口: 8081")
	fmt.Println("接口路径: /ban/v2")

	http.HandleFunc("/ban/v2", banHandler)
	http.ListenAndServe(":8081", nil)
}

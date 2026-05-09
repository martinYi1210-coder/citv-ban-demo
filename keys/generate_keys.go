package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	// 生成调用方(CITV)密钥对
	generateKeyPair("citv", 4096)
	// 生成被调用方(SaaS)密钥对
	generateKeyPair("saas", 4096)
	fmt.Println("密钥对生成完成！(4096位)")
	fmt.Println("citv私钥: keys/citv_private.pem")
	fmt.Println("citv公钥: keys/citv_public.pem")
	fmt.Println("saas私钥: keys/saas_private.pem")
	fmt.Println("saas公钥: keys/saas_public.pem")
}

func generateKeyPair(name string, bits int) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		fmt.Printf("生成私钥失败: %v\n", err)
		os.Exit(1)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	os.WriteFile(fmt.Sprintf("%s_private.pem", name), privateKeyPEM, 0600)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Printf("生成公钥失败: %v\n", err)
		os.Exit(1)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	os.WriteFile(fmt.Sprintf("%s_public.pem", name), publicKeyPEM, 0644)
}

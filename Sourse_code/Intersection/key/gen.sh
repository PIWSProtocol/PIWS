#!/bin/sh

echo Generate CA key:
openssl genrsa -passout pass:1111 -des3 -out ca.key 2048

echo Generate CA certificate:
openssl req -passin pass:1111 -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/C=CN/ST=FuJian/L=XiaMen/O=YaXon/OU=gRPC/CN=CA"
 
echo Generate server key:
openssl genrsa -passout pass:1111 -des3 -out server_privatekey.pem 2048
 
echo Generate server signing request:
openssl req -passin pass:1111 -new -key server_privatekey.pem -out server_csr.pem -subj "/C=CN/ST=FuJian/L=XiaMen/O=YaXon/OU=gRPC/CN=YD2"
 
echo Self-sign server certificate:
openssl x509 -req -passin pass:1111 -days 3650 -in server_csr.pem -CA ca.crt -CAkey ca.key -CAcreateserial -out server_self_signed_crt.pem
 
echo Remove passphrase from server key:
openssl rsa -passin pass:1111 -in server_privatekey.pem -out server_privatekey.pem
 
echo Generate client key
openssl genrsa -passout pass:1111 -des3 -out client_privatekey.pem 2048
 
echo Generate client signing request:
openssl req -passin pass:1111 -new -key client_privatekey.pem -out client_csr.pem -subj "/C=CN/ST=FuJian/L=XiaMen/O=YaXon/OU=gRPC/CN=YD1"
 
echo Self-sign client certificate:
openssl x509 -passin pass:1111 -req -days 3650 -in client_csr.pem -CA ca.crt -CAkey ca.key -CAcreateserial -out client_self_signed_crt.pem
 
echo Remove passphrase from client key:
openssl rsa -passin pass:1111 -in client_privatekey.pem -out client_privatekey.pem
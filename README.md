# WSS Certificate Generator

Used to generate self signed certificates which can be used by core and the java cloud library for starting a secure websocket connection

- Core only requires the `PEM` file which contains the certificate
- The Java Cloud app requires the `JKS` keystore file and a password to access this file

## Requirements
1. OpenSSL (`which openssl`)
2. Java Keytool (`which keytool`)
3. Python Expect library (`python3 -c "import pexpect"`)
```
pip3 install pexpect
```
## How to use

### General format
> ./gen_certs.py <_host_ip_address_> [**-flag** _value_|**-flag**]

1. `./gen_certs.py <host_ip_address>`  
Generates the privatekey, certificate, keystore and JKS files

2. `./gen_certs.py <host_ip_address> -key privatekey.key`  
Generates the certificate, keystore and JKS files

3. `./gen_certs.py <host_ip_address> -key privatekey.key -cert cert.pem`  
Generates the keystore and JKS files

4. `./gen_certs.py <host_ip_address> ... -keystore keystore.p12`  
Generates the JKS file

### Generating certificate authority(CA) to sign generated certificate
Add CA flag
> ./gen_certs.py <_host_ip_address_> [**-flag** _value_|**-flag**] **-CA** [**-flag** _value_|**-flag**]

1. `./gen_certs.py <host_ip_address> -CA`  
Generates the CA key, CA certificate, server key, server certificate signing request, server certificate, keystore and JKS files

2. `./gen_certs.py <host_ip_address> -CA -ca_key ca.key`  
Generates the CA certificate, server key, server certificate signing request, server certificate, keystore and JKS files

3. `./gen_certs.py <host_ip_address> -CA -ca_key ca.key -ca_cert ca.cert`  
Generates the server key, server certificate signing request, server certificate, keystore and JKS files

4. `./gen_certs.py <host_ip_address> -CA -ca_key ca.key -ca_cert ca.cert -key privatekey.key`  
Generates the server certificate signing request, server certificate, keystore and JKS files

5. `./gen_certs.py <host_ip_address> -CA -ca_key ca.key -ca_cert ca.cert -key privatekey.key -sign_req req.csr`  
Generates the server certificate, keystore and JKS files

6. `./gen_certs.py <host_ip_address> -CA ... -key privatekey.key -cert cert.pem`  
Generates the keystore and JKS files

7. `./gen_certs.py <host_ip_address> -CA ... -keystore keystore.p12`  
Generates the JKS file

Run this to remove all certs, keys and keystores ``` rm -f *.pem *.key *.p12 *.jks *.csr``` or `make clean`

## Testing

Can test the certificates and private keys for a WSS connection using the `TestWSSServer.py` and `TestWSSClient.py`

1. `./TestWSSServer.py`  
Set the correct configurations for the ws_settings
``` json
ws_settings = {
    "ip" : '<ip used to generate certificate>',
    "port" : '<port number>',
    "key_file" : '<name of privatekey file>',
    "cert_file" : '<name of PEM certificate file>',
    "cert_path" : '<Path prefix, if privatekey and certificate are in a different directory>'
}
```

2. `./TestWSSClient.py`  
Set the correct configurations for the ws_settings
``` json
ws_settings = {
    "ip" : '<ip used to generate certificate>',
    "port" : '<port number>',
    "cert_file" : '<name of PEM certificate file>',
    "cert_path" : '<Path prefix, if certificate is in a different directory>'
}
```
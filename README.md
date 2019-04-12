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
General format
> ./gen_certs.py <_host_ip_address_> [**-flag** _value_|**-flag**]

1. `./gen_certs.py <host_ip_address>`  
Generates the privatekey, certificate, keystore and JKS files

2. `./gen_certs.py <host_ip_address> -key privatekey.key`  
Generates the certificate, keystore and JKS files

3. `./gen_certs.py <host_ip_address> -key privatekey.key -cert cert.pem`  
Generates the keystore and JKS files

4. `./gen_certs.py <host_ip_address> ... -keystore keystore.p12`  
Generates the JKS file

Run this to remove all certs, keys and keystores ``` rm -f *.pem *.key *.p12 *.jks *.csr``` 
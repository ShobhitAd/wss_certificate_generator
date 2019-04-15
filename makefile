install:
	which pip3
	pip3 install pexpect

test:
	which openssl
	which keytool
	python3 -c "import pexpect"

clean:
	rm -f *.pem *.key *.p12 *.jks *.csr *.srl
install:
	which pip3
	pip3 install pexpect

check:
	which openssl
	which keytool
	python3 -c "import pexpect"

test:
	if pgrep python3; then pkill python3; fi
	python3 TestWSSServer.py &
	sleep 2 
	# Enter 'exit' command to exit client
	python3 TestWSSClient.py
	if pgrep python3; then pkill python3; fi

clean:
	rm -f *.pem *.key *.p12 *.jks *.csr *.srl
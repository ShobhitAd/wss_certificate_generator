#!/usr/bin/env python3

import sys, os
import subprocess
import pexpect
# from pprint import pprint

class CertCommands():
  def gen_key(self, key_file):
    # openssl genrsa -out [KEY] 4096
    gen_command = "openssl genrsa -out %s 4096" % (key_file)
    subprocess.call(gen_command.split(' '), stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)

  def gen_cert(self, key_file, cert_file, inputs):
    self.check_inputs('GENERATE CERTIFICATE', inputs, required=['ip'])
    #openssl req -new -x509 -key [KEY] -out [CERTIFICATE] -days 1095
    gen_command = "openssl req -new -x509 -key %s -out %s -days 1095" % (key_file, cert_file)
    gen_process = subprocess.Popen(gen_command.split(' '), stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    gen_input='.\n.\n.\n.\n.\n%s\n.\n' % inputs['ip']
    gen_process.communicate(input=bytes(gen_input, 'utf-8'))
    gen_process.wait()

  def gen_key_and_cert(self, key_file, cert_file, inputs):
    self.check_inputs('GENERATE KEY AND CERTIFICATE', inputs, required=['ip'])
    # openssl req -newkey rsa:2048 -nodes -keyout [KEY] -x509 -days 365 -out [CERTIFICATE]
    gen_command = "openssl req -newkey rsa:2048 -nodes -keyout %s -x509 -days 1095 -out %s" % (key_file, cert_file)
    gen_process = subprocess.Popen(gen_command.split(' '), stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    gen_input='.\n.\n.\n.\n.\n%s\n.\n' % inputs['ip']
    gen_process.communicate(input=bytes(gen_input, 'utf-8'))
    gen_process.wait()

  def gen_signing_request(self, key_file, sign_req_file, inputs):
    self.check_inputs('GENERATE SIGNING REQUEST', inputs, required=['ip'])
    # openssl req -new -key [KEY] -out [SIGNING_REQUEST]
    gen_command = "openssl req -new -key %s -out %s" % (key_file, sign_req_file)
    gen_process = subprocess.Popen(gen_command.split(' '), stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    gen_input='.\n.\n.\n.\n.\n%s\n.\n\n\n' % inputs['ip']
    gen_process.communicate(input=bytes(gen_input, 'utf-8'))
    gen_process.wait()

  def gen_CA_signed_cert(self, ca_key_file, ca_cert_file, sign_req_file, cert_file):
    #openssl x509 -req -in [SIGNING_REQUEST] -CA [CA_CERTIFICATE] -CAkey [CA_KEY] -CAcreateserial -out [CERTIFICATE] -days 500 -sha256
    gen_command = "openssl x509 -req -in %s -CA %s -CAkey %s -CAcreateserial -out %s -days 500 -sha256" \
      % (sign_req_file, ca_cert_file, ca_key_file, cert_file)
    subprocess.call(gen_command.split(' '), stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)

  def gen_keystore(self, key_file, cert_file, keystore_file, inputs):
    self.check_inputs('GENERATE KEYSTORE', inputs, required=['keystore_password'])
    #openssl pkcs12 -export -out [KEYSTORE] -inkey [KEY] -in [CERT]
    gen_process = pexpect.spawn("openssl pkcs12 -export -out %s -inkey %s -in %s" % (keystore_file, key_file, cert_file))
    gen_process.expect("Enter Export Password")
    gen_process.sendline(inputs['keystore_password'])
    gen_process.expect("Verifying - Enter Export Password")
    gen_process.sendline(inputs['keystore_password'])
    gen_process.expect(pexpect.EOF)

  def gen_jks(self, keystore_file, jks_file, inputs):
    self.check_inputs('GENERATE JAVA KEYSTORE', inputs, required=['jks_password', 'keystore_password'])
    # keytool -importkeystore -destkeystore [JKS] -srcstoretype PKCS12 -srckeystore [KEYSTORE]
    gen_command = "keytool -importkeystore -destkeystore %s -srcstoretype PKCS12 -srckeystore %s" % (jks_file, keystore_file)
    gen_process = subprocess.Popen(gen_command.split(' '), stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    gen_input='%s\n%s\n%s\n' % (inputs['jks_password'], inputs['jks_password'], inputs['keystore_password'])
    gen_process.communicate(input=bytes(gen_input, 'utf-8'))
    gen_process.wait()

  def check_inputs(self, tag, inputs, required):
    for arg in required:
      if arg not in inputs:
        print("%s: Missing input argument(%s)" % (tag, arg))
        exit(1)

class CertManager():
    def __init__(self, params):
        self.PARAMS = params
        self.KEYSTORE_PASSWORD = 'default_password'
        self.JKS_PASSWORD = 'default_password'
        self.COMMANDS = CertCommands()
        self.DEFAULT_FILENAMES = {
          'key' : 'privatekey.key',
          'cert' : 'cert.pem',
          'keystore': 'keystore.p12',
          'jks': 'jkeystore.jks',
          'ca_key': 'CAkey.key',
          'ca_cert': 'CAcert.pem',
          'sign_req' : 'signRequest.csr' 
        }
        
    def generate(self):
        # Validate file args
        for flag in ['key', 'cert', 'keystore', 'jks', 'ca_key', 'ca_cert', 'sign_req']:
            if flag in self.PARAMS:
                if not os.path.exists(self.PARAMS[flag]):
                    print('%s file does not exist' % flag.upper())
                    exit(1)
                print('%s specified' % flag.upper())
        
        if 'jks' in self.PARAMS:
            print('Why are you here')
            exit(0)
        
        if 'CA' in self.PARAMS:
          self.gen_CA_key_and_cert()
          self.gen_CA_cert()
          self.gen_Server_key()
          self.gen_Server_cert_signing_request()
          self.gen_Server_cert()
        else:
          self.gen_key_and_cert()
          self.gen_cert()
        self.gen_keystore()
        self.gen_jks()

    def gen_cert(self):
        if self.some_req('keystore', 'cert'):
            return
        if not self.all_req('ip', 'key'):
            print('Missing required parameters')     
            exit(1)   

        print('Generating cert based on private key')
        self.COMMANDS.gen_cert(self.PARAMS['key'], self.DEFAULT_FILENAMES['cert'], {'ip': self.PARAMS['ip']} )

        self.PARAMS['cert'] = self.DEFAULT_FILENAMES['cert']

    def gen_key_and_cert(self):
        if self.some_req('keystore', 'key', 'cert'):
            return
        if not self.all_req('ip'):
            print('Missing required parameters')     
            exit(1)      

        print('Generating private key and cert')
        self.COMMANDS.gen_key_and_cert(self.DEFAULT_FILENAMES['key'], self.DEFAULT_FILENAMES['cert'], {'ip': self.PARAMS['ip']} )

        self.PARAMS['key'] = self.DEFAULT_FILENAMES['key']
        self.PARAMS['cert'] = self.DEFAULT_FILENAMES['cert']

    def gen_keystore(self):
        if self.some_req('keystore'):
            return
        if not self.all_req('key', 'cert'):
            print('Missing required parameters')     
            exit(1)   

        print('Generating keystore based on cert and private key')
        self.COMMANDS.gen_keystore(self.PARAMS['key'], self.PARAMS['cert'], self.DEFAULT_FILENAMES['keystore'], {'keystore_password': self.KEYSTORE_PASSWORD} )

        self.PARAMS['keystore'] = self.DEFAULT_FILENAMES['keystore']
    
    def gen_jks(self):
        if self.some_req('jks'):
            return
        if not self.all_req('keystore'):
            print('Missing required parameters')     
            exit(1)

        print('Generating JKS based on keystore')
        self.COMMANDS.gen_jks(self.PARAMS['keystore'], self.DEFAULT_FILENAMES['jks'], {'keystore_password': self.KEYSTORE_PASSWORD, 'jks_password': self.JKS_PASSWORD} )

        self.PARAMS['jks'] = self.DEFAULT_FILENAMES['jks']

### CA methods
    def gen_CA_cert(self):
        if self.some_req('keystore', 'ca_cert', 'cert'):
            return
        if not self.all_req('ip', 'ca_key'):
            print('Missing required parameters')     
            exit(1)   

        print('Generating CA cert based on CA private key')
        self.COMMANDS.gen_cert(self.PARAMS['ca_key'], self.DEFAULT_FILENAMES['ca_cert'], {'ip': self.PARAMS['ip'] + ' CA'} )

        self.PARAMS['ca_cert'] = self.DEFAULT_FILENAMES['ca_cert']

    def gen_CA_key_and_cert(self):
        if self.some_req('keystore', 'ca_key', 'ca_cert', 'cert'):
            return
        if not self.all_req('ip'):
            print('Missing required parameters')     
            exit(1)      

        print('Generating CA private key and cert')
        self.COMMANDS.gen_key_and_cert(self.DEFAULT_FILENAMES['ca_key'], self.DEFAULT_FILENAMES['ca_cert'], {'ip': self.PARAMS['ip'] + ' CA'} )

        self.PARAMS['ca_key'] = self.DEFAULT_FILENAMES['ca_key']
        self.PARAMS['ca_cert'] = self.DEFAULT_FILENAMES['ca_cert']

    def gen_Server_key(self):
        if self.some_req('keystore', 'key'):
            return
        if not self.all_req('ip'):
            print('Missing required parameters')     
            exit(1)      

        print('Generating Server private key')
        self.COMMANDS.gen_key(self.DEFAULT_FILENAMES['key'])

        self.PARAMS['key'] = self.DEFAULT_FILENAMES['key']

    def gen_Server_cert_signing_request(self):
        if self.some_req('keystore', 'cert', 'sign_req'):
            return
        if not self.all_req('ip', 'key'):
            print('Missing required parameters')     
            exit(1)      

        print('Generating Server certificate signing request')
        self.COMMANDS.gen_signing_request(self.PARAMS['key'], self.DEFAULT_FILENAMES['sign_req'], {'ip': self.PARAMS['ip']})

        self.PARAMS['sign_req'] = self.DEFAULT_FILENAMES['sign_req']

    def gen_Server_cert(self):
        if self.some_req('keystore', 'cert'):
            return
        if not self.all_req('ip', 'sign_req', 'ca_key', 'ca_cert'):
            print('Missing required parameters')     
            exit(1)      

        print('Generating Server certificate(signed by CA)')
        self.COMMANDS.gen_CA_signed_cert(self.PARAMS['ca_key'], self.PARAMS['ca_cert'], self.PARAMS['sign_req'], self.DEFAULT_FILENAMES['cert'])

        self.PARAMS['cert'] = self.DEFAULT_FILENAMES['cert']

    def all_req(self, *flags):
        res = True
        for f in flags:
            if f not in self.PARAMS:
                res = False
        return res

    def some_req(self, *flags):
        res = False
        for f in flags:
            if f in self.PARAMS:
                res = True
        return res


def isFlag(arg):
  return len(arg) != 0 and arg[0] == '-'

def parseArgs():
    if len(sys.argv) < 2:
        print("Minimum required argument: host ip address/hostname")
        exit(1)

    params = {}
    params['ip'] = sys.argv[1]
  
    if isFlag(params['ip']):
      print("Invalid ip value" + params['ip'])
      exit(1)

    prevArg = ''
    for i in range(2, len(sys.argv)):
      arg = sys.argv[i]
      if isFlag(arg):# FLAG
        # Add flag to dictionary
        params[arg[1:]] = None
      else:
        if isFlag(prevArg):
          # Assign value to flag
          params[prevArg[1:]] = arg
        else:
          print('Not a flag: %s' % arg)
          exit(1)
      prevArg = arg

    return params


def main():
    params = parseArgs()
    print(params)
    CM = CertManager(params)
    CM.generate()
    
if __name__ == '__main__':
    main()
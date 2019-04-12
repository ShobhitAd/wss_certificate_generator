#!/usr/bin/env python3

import sys, os
import subprocess
import pexpect
# from pprint import pprint

class CertManager():
    def __init__(self, params):
        self.PARAMS = params
        self.KEYSTORE_PASSWORD = 'default_password'
        self.JKS_PASSWORD = 'default_password'
    def generate(self):
        # Validate file args
        for flag in ['key', 'cert', 'keystore', 'jks']:
            if flag in self.PARAMS:
                if not os.path.exists(self.PARAMS[flag]):
                    print('%s file does not exist' % flag.upper())
                    exit(1)
                print('%s specified' % flag.upper())
        
        if 'jks' in self.PARAMS:
            print('Why are you here')
            exit(0)
        
        self.gen_key_and_cert()
        self.gen_cert()
        self.gen_keystore()
        self.gen_jks()
        
    def gen_key_and_cert(self):
        if self.some_req('keystore', 'key', 'cert'):
            return
        if not self.all_req('ip'):
            print('Missing required parameters')     
            exit(1)   
        print('Generating private key and cert')
        # openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
        gen_command = "openssl req -newkey rsa:2048 -nodes -keyout privatekey.key -x509 -days 1095 -out cert.pem"
        gen_process = subprocess.Popen(gen_command.split(' '), stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
        gen_input='.\n.\n.\n.\n.\n%s\n.\n' % self.PARAMS['ip']
        gen_process.communicate(input=bytes(gen_input, 'utf-8'))
        gen_process.wait()

        self.PARAMS['key'] = 'privatekey.key'
        self.PARAMS['cert'] = 'cert.pem'

    def gen_cert(self):
        if self.some_req('keystore', 'cert'):
            return
        if not self.all_req('ip', 'key'):
            print('Missing required parameters')     
            exit(1)   

        print('Generating cert based on private key')
        #openssl req -new -x509 -key key.pem -out cacert.pem -days 1095
        gen_command = "openssl req -new -x509 -key %s -out cert.pem -days 1095" % self.PARAMS['key']
        gen_process = subprocess.Popen(gen_command.split(' '), stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
        gen_input='.\n.\n.\n.\n.\n%s\n.\n' % self.PARAMS['ip']
        gen_process.communicate(input=bytes(gen_input, 'utf-8'))
        gen_process.wait()

        self.PARAMS['cert'] = 'cert.pem'

    def gen_keystore(self):
        if self.some_req('keystore'):
            return
        if not self.all_req('key', 'cert'):
            print('Missing required parameters')     
            exit(1)   

        print('Generating keystore based on cert and private key')
        #openssl pkcs12 -export -out keystore.p12 -inkey privatekey.key -in cert.pem
        gen_process = pexpect.spawn("openssl pkcs12 -export -out keystore.p12 -inkey %s -in %s" % (self.PARAMS['key'], self.PARAMS['cert']))
        gen_process.expect("Enter Export Password")
        gen_process.sendline(self.KEYSTORE_PASSWORD)
        gen_process.expect("Verifying - Enter Export Password")
        gen_process.sendline(self.KEYSTORE_PASSWORD)
        gen_process.expect(pexpect.EOF)

        self.PARAMS['keystore'] = 'keystore.p12'
    
    def gen_jks(self):
        if self.some_req('jks'):
            return
        if not self.all_req('keystore'):
            print('Missing required parameters')     
            exit(1)   

        print('Generating JKS based on keystore')
        # keytool -importkeystore -destkeystore keystore.jks -srcstoretype PKCS12 -srckeystore keystore.p12
        gen_command = "keytool -importkeystore -destkeystore jkeystore.jks -srcstoretype PKCS12 -srckeystore %s" % (self.PARAMS['keystore'])
        gen_process = subprocess.Popen(gen_command.split(' '), stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
        gen_input='%s\n%s\n%s\n' % (self.JKS_PASSWORD, self.JKS_PASSWORD, self.KEYSTORE_PASSWORD)
        gen_process.communicate(input=bytes(gen_input, 'utf-8'))
        gen_process.wait()

        # print(out[0].decode())

        self.PARAMS['jks'] = 'jkeystore.jks'
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
        print("Minimum required argument: host ip address")
        exit(1)

    params = {}
    params['ip'] = sys.argv[1]
    
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
          exit(0)
      prevArg = arg

    return params


def main():
    params = parseArgs()
    print(params)
    CM = CertManager(params)
    CM.generate()
    
if __name__ == '__main__':
    main()
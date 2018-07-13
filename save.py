import ast, base64
from Crypto.Cipher import XOR
import pyperclip
import sys
from subprocess import run
from threading import Timer
import getpass
import os

def encrypt(key, plaintext):
  cipher = XOR.new(key)
  return base64.b64encode(cipher.encrypt(plaintext))

def decrypt(key, ciphertext):
  cipher = XOR.new(key)
  return cipher.decrypt(base64.b64decode(ciphertext))

def createNewPass(userID,  key):
	password = getpass.getpass(prompt='Enter password:')
	passList = readFile(key)
	passList[userID] = password
	saveFile(str(passList), key)

def saveFile(text, key):
	text = encrypt(key,text)
	file = open('passwords.txt','w')
	text = text.decode('utf-8')
	file.write(text)
	file.close()

def readFile(key):
	file = open('passwords.txt', 'r')
	text = file.read()
	file.close()
	if text == '':
		saveFile(b'{}', key)
	text = (decrypt(key, text)).decode('utf-8')
	try:
		passwords = ast.literal_eval(text)
		return passwords
	except SyntaxError:
		print('Wrong key')
		sys.exit()

def save():
	if os.geteuid() != 0:
		print('''You don't have root privileges''')
		sys.exit()

	if len(sys.argv) < 2:
		print('Usage: command [userID]')
		sys.exit()

	key = getpass.getpass(prompt='Enter key:')
	createNewPass(sys.argv[1], key)

save()
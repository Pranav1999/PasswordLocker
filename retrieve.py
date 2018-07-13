import ast, base64
from Crypto.Cipher import XOR
import pyperclip
import sys
from subprocess import run
from threading import Timer
import getpass
import os

def decrypt(key, ciphertext):
  cipher = XOR.new(key)
  return cipher.decrypt(base64.b64decode(ciphertext))

def clearClipboard():
	run(["xsel","-bc"])

def readPass(userID, passList):
	if userID in passList.keys():
		pyperclip.copy(passList[userID])
		t = Timer(5.0, clearClipboard)
		t.start()
	else:
		print('No such userID exists')
		sys.exit()


def readFile(key):
	file = open('passwords.txt', 'r')
	text = file.read()
	file.close()
	if text == '':
		print('No saved passwords')
		sys.exit()
	text = (decrypt(key, text)).decode('utf-8')
	try:
		passwords = ast.literal_eval(text)
		return passwords
	except SyntaxError:
		print('Wrong key')
		sys.exit()

def retrieve():
	if os.geteuid() != 0:
		print('''You don't have root privileges''')
		sys.exit()

	if len(sys.argv) < 2:
		print('Usage: command [userID]')
		sys.exit()

	key = getpass.getpass(prompt='Enter key:')
	passwords=readFile(key)
	readPass(sys.argv[1],passwords)

retrieve()

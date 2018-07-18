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

def deletePass(userID,  key):
	passList = readFile(key)
	del passList[userID]
	saveFile(str(passList), key)

def saveFile(text, key):
    text = encrypt(key,text)
    file = open('passwords.txt','w')
    text = text.decode('utf-8')
    file.write(text)
    file.close()

def readFile(key):
    try:
        file = open('passwords.txt', 'r')
    except FileNotFoundError:
        file = open('passwords.txt', 'a')
        file.close()
        file = open('passwords.txt', 'r')
    text = file.read()
    if text == '':
        saveFile(b'{}', key)
        text = file.read()
    file.close()
    text = (decrypt(key, text)).decode('utf-8')
    try:
        passwords = ast.literal_eval(text)
        return passwords
    except SyntaxError:
        print('Wrong key')
        sys.exit()

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

def password_locker():
    if os.geteuid() != 0:
        print('''You don't have root privileges''')
        sys.exit()

    if len(sys.argv) < 3:
        print('Usage: command [save/retrieve] [userID]')
        sys.exit()

    key = getpass.getpass(prompt='Enter key:')

    if sys.argv[1] == "save":
        createNewPass(sys.argv[2], key)
    elif sys.argv[1] == "retrieve":
        passwords=readFile(key)
        readPass(sys.argv[2],passwords)
    elif sys.argv[1] == "delete":
    	deletePass(sys.argv[2], key)
    else:
        print('Usage: command [save/retrieve/delete] [userID]')
        sys.exit()

password_locker()

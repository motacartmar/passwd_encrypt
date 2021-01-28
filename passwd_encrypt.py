import sys
import os
from base64 import decode, encode, urlsafe_b64encode as b64e, urlsafe_b64decode as b64d


parent_dir = os.path.abspath(os.path.dirname(__file__))
libraries_dir = os.path.join(parent_dir, 'libraries')

sys.path.append(libraries_dir)

import PySimpleGUI as sg
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PySimpleGUI.PySimpleGUI import InputText, Text, WIN_CLOSED
from tkinter import font
from tkinter.constants import CENTER
import secrets

backend = default_backend()
iterations = 100_000

def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))

def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)



mode = ['Encrypt','Decrypt']
mode_select = mode[0]
passwd_text = 'Insert Passwd'

layout = [[sg.Text('ENCRYPT YOUR PASSWORDS',size=(55,1), justification= 'center',font=('Any 15'))],
          [sg.Text(f'Choose .txt file to {mode_select}',size=(30,1), justification='left', key='-TEXT_PATH-'), 
           sg.InputText('Folder path',size=(35,1), key=('-PATH-')), sg.FileBrowse(key='-PATH-', size=(5,1), font=('any 10'))],
          [sg.Text('You need to:',size=(30,1), justification='left'), sg.InputCombo(mode, default_value=mode_select,size=(34,1), key='-COMBO-', enable_events=True)],
          [sg.Text(f'Passwd to {mode_select}',size=(16,1),justification='left', key='-PASSWD_TEXT-'), sg.Text(passwd_text, size=(14,1), key='-PASSWD_LEN-', font=('any 10')), 
           sg.InputText(size=(35,1) , key='-PASSWD-', password_char='*', enable_events=True)],
          [sg.Button(mode_select, size=(59,1), font=('any 15'),button_color=('black', '#00FF00'), key=('-SUBMIT-'))]
         ] 


window = sg.Window('Encrypter', layout,
                    font=('Any 12'),
                    auto_size_text=True,
                    auto_size_buttons=True
                    )

while True:
    event, value = window.read()
    if event == sg.WIN_CLOSED:
        break
    if value['-COMBO-'] != mode_select :
        mode_select = value['-COMBO-']
        window['-PASSWD_TEXT-'].update(f'Passwd to {mode_select}')
        window['-TEXT_PATH-'].update(f'Choose .txt file to {mode_select}')
        window['-SUBMIT-'].update(mode_select)

    passwd = value['-PASSWD-']
    passwd_len = len(passwd)
    if passwd_len == 0:
        passwd_text = 'Insert Passwd'
        window['-PASSWD_LEN-'].update(passwd_text)
    elif passwd_len <= 5 and passwd_len > 0:
        passwd_text = 'Weak Passwd'
        window['-PASSWD_LEN-'].update(passwd_text)
    elif passwd_len > 5 and passwd_len <= 9:
        passwd_text = 'Medium Passwd'
        window['-PASSWD_LEN-'].update(passwd_text)
    else:
        passwd_text = 'Strong Passwd'
        window['-PASSWD_LEN-'].update(passwd_text)
    

    if event in '-SUBMIT-':
        passwr = value['-PASSWD-']
        path = value['-PATH-']

        #print(password_encrypt(message=b'teste', password='123'))
        #print(password_decrypt(token=b'kwiih8B8aiHVugUUv5uwIQABhqCAAAAAAGAPWl5CaNurDl2TqL1tTmkpETSbGgAHkEZlNk6sO7IuRF7IeyEiRkrdk3PZbM71fgqJsBeBjy4tLpeckpj7-RTRZe2z', password='123'))
        content = ''

        try:

            if str(path).endswith('.txt') and passwd_len > 2:
                if mode_select == mode[0]:
                    with open(path, 'r') as f:
                        lines = f.readlines()
                        i = 0
                        for line in lines:
                            encrypted = password_encrypt(message= str.encode(line), password= passwd)
                            #print(encrypted.decode())   #####
                            content += encrypted.decode() + '\n'
                        with open(path, 'w') as b:
                            b.write(content) 
                            print(content)
            
                else:
                    with open(path, 'rb') as f:
                        lines = f.readlines()
                        for line in lines:
                            bytedecode = line.decode().split('\r\n')
                            #print(bytedecode)
                            if bytedecode[0] != ' ':
                                byte = str.encode(bytedecode[0])
                                #print(byte)
                                decryptedbyte = password_decrypt(token= byte, password= passwd)
                                decrypted = decryptedbyte.decode('UTF-8')
                                #print(decryptedbyte.decode('UTF-8'))
                                content += decrypted 
                
                    with open(path, 'w') as f:
                        f.write(content)
                        print(content)
                        
            elif not str(path).endswith('.txt') and passwd_len < 5:
                sg.popup_error('Weak Password and select .txt file')
            elif passwd_len <= 5 and str(path).endswith('.txt'):
                sg.popup_error(f'Weak Password {passwd_len} digitis')
            else:
                sg.popup_error('Select .txt file')
        except:
            sg.popup_error('error')
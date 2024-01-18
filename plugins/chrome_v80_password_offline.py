#!/usr/bin/python3

import os
import sqlite3
from Cryptodome.Cipher import AES
import plugins.chrome_dpapi

def get_master_key():
    f= open("decrypted.bin","rb")
    master_key=f.read()
    f.close()
    return master_key


def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)


def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)


def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = generate_cipher(master_key, iv)
        decrypted_pass = decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()  # remove suffix bytes
        return decrypted_pass
    except Exception as e:
        # print(str(e))
        return "Credentials extraction error maybe enc_key is wrong or Chrome version < 80"


def Chrome_decryptor(dir, folder, mk, password, sid):
    output = ''
    ret = plugins.chrome_dpapi.Dpapi_decrypt(dir, mk, password, sid)
    ret.main()
    enc_key = ret.return_key()
    if enc_key != '':
        login_db = os.path.join(dir, folder, 'Login Data')
        conn = sqlite3.connect(login_db)
        cursor = conn.cursor()
        cursor.execute("SELECT action_url, username_value, password_value FROM logins")
        for r in cursor.fetchall():
            url = r[0]
            username = r[1]
            encrypted_password = r[2]
            decrypted_password = decrypt_password(encrypted_password, enc_key)
            output += f'{"*" * 50}\nURL: {url}\nUser Name: {username}\nPassword: {decrypted_password}\n'
        cursor.close()
        conn.close()
        return output
    else:
        raise


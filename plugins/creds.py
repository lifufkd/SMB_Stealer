
from plugins.DPAPI.DPAPI.masterkey import MasterKeyPool
from plugins.DPAPI.DPAPI.credfile import CredFile


class Creds(object):
    """
    User class for DPAPI functions
    """

    def __init__(self, sid, password, dir_sid):
        __sid = sid
        __password = password
        __dir = dir_sid

        self.umkp = MasterKeyPool()
        self.umkp.load_directory(__dir)
        for ok, r in self.umkp.try_credential(sid=__sid, password=__password):
            pass

    def decrypt_cred(self, credfile):
        """
        Decrypt Credential Files
        """
        if self.umkp:
            with open(credfile, 'rb') as f:
                c = CredFile(f.read())
            ok, msg = c.decrypt(self.umkp, credfile)
            return ok, msg
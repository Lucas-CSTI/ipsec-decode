# -*- coding: UTF-8 -*-
#/**
# * Software Name : WebServer for IPsec (GPL)
# * Function: Webserver for IPsec
# * Version : 1.0
# *
# *--------------------------------------------------------
# * File Name : ipsec.py
# * Authors   : Yi-Hsueh (Lucas) Tsai
# * License   : GPL
# *--------------------------------------------------------
#*/

# ╔═════════════════════╗
# ║ built-ins libraries ║
# ╚═════════════════════╝
from sys          import argv
from os.path      import isfile, split
from datetime     import date
from calendar     import month_abbr
from json         import loads, dumps
from binascii     import unhexlify
from argparse     import ArgumentParser, RawTextHelpFormatter

# ╔═════════════╗
# ║ GPL license ║
# ╚═════════════╝
try:
    from scapy.all            import rdpcap, wrpcap
    from scapy.layers.inet    import IP, UDP
    from scapy.layers.isakmp  import ISAKMP
    from scapy.layers.ipsec   import SecurityAssociation, IPSecIntegrityError, ESP, AH
except ImportError as error:
    print('scapy library are required for WebServerIPsec')
    raise(error)

def ParseXfrm(filename):
    ip_xfrm_state = {}
    with open(filename, 'r') as file:
        for line in file:
            data = line.strip().split(' ')
            if (data[0] == 'proto') and (data[1] == 'esp') and (data[2] == 'spi'):
                index = int(data[3], 0)
                ip_xfrm_state[index] = {'spi': data[3]}
            elif data[0] == 'auth-trunc':
                auth_algo = {'hmac(sha256)': 'SHA2-256-128'}[data[1]]
                ip_xfrm_state[index].update({'auth_algo': auth_algo, 'auth_key': data[2][2:]})
            elif data[0] == 'enc':
                crypt_algo = {'cbc(aes)': 'AES-CBC'}[data[1]]
                ip_xfrm_state[index].update({'crypt_algo': crypt_algo, 'crypt_key': data[2][2:]})
    return ip_xfrm_state

# ╔══════╗
# ║ main ║
# ╚══════╝
def main():

    BuildDate = date(2023, 8, 25)
    server_address=('127.0.0.1', 9000)
    BuildDate = date(2023, 8, 25)
    description = 'Version 1.0β (CSTI)\nAuthors: Yi-Hsueh Tsai (email: lucas@iii.org.tw)\nBuild Date : %s %s %s' % (BuildDate.year, month_abbr[BuildDate.month], BuildDate.day)
    parser = ArgumentParser(description=description, formatter_class=RawTextHelpFormatter)
    parser.add_argument('-l',    '--logfile',            help='Log file for SCAS')
    parser.add_argument('-ixs',  '--ip-xfrm-state',      help='ip-xfrm-state file for SCAS')

    args = parser.parse_args(argv[1:])
    if (args.logfile is None) or (not isfile(args.logfile)):
        print('Missing log file!')
    elif (args.ip_xfrm_state is None) or (not isfile(args.ip_xfrm_state)):
        print('Missing ip-xfrm-state files!')
    else:
        ip_xfrm_state = ParseXfrm(args.ip_xfrm_state)
        filename = '%s/decrypted-%s' % split(args.logfile)
        sa_list, error = {}, []
        for spi, value in ip_xfrm_state.items():
            sa_list[spi] = SecurityAssociation(ESP, spi=int(spi),
                                crypt_algo=value['crypt_algo'], crypt_key=unhexlify(value['crypt_key']),
                                auth_algo=value['auth_algo'], auth_key=unhexlify(value['auth_key']))
        packet = []
        for message in rdpcap(args.logfile):
            ip = message.getlayer(IP)
            if ip is not None:
                isakmp, esp = None, None
                if   ip.proto == 17: # UDP
                    udp = ip.getlayer(UDP)
                    if udp.dport == 500: # ISAKMP
                        if 'ISAKMP' in ip:
                            isakmp = ip[ISAKMP]
                    elif udp.dport == 4500: # ESP
                        if 'ESP' in udp:
                            esp = udp.getlayer(ESP)
                elif ip.proto == 50: # ESP
                    esp = ip.getlayer(ESP)
                if   isakmp is not None: # ISAKMP
                    packet.append(ip)
                elif esp is not None: # ESP
                    if esp.spi in sa_list:
                        sa = sa_list[esp.spi]
                        try:
                            dec = sa.decrypt(ip)
                        except IPSecIntegrityError as error:
                            error.append('<<<IPSec Integrity Error>>>')                   
                        except Exception as error:
                            error.append(str(error))
                        else:
                            packet.append(dec)
        wrpcap(filename, packet)
        print('-l %s -ixs %s' % (filename, args.ip_xfrm_state))

main()
# -*- coding: UTF-8 -*-
#/**
# * Software Name : WebServer for IPsec decoder (GPL)
# * Function: Webserver for IPsec decoder
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
from os.path      import split
from datetime     import date
from calendar     import month_abbr
from json         import loads, dumps
from binascii     import unhexlify
from http.server  import HTTPServer, SimpleHTTPRequestHandler

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

# ╔══════════════════════════╗
# ║ HTTPRequestHandler class ║
# ╚══════════════════════════╝
class HTTPRequestHandler(SimpleHTTPRequestHandler):

    def __init__(self):
        pass

    def __call__(self, *args, **kwargs):
        super().__init__(*args, **kwargs) # Handle a request

    def response(self, code, json=None):
        self.send_response(code)
        self.send_header('Content-type', 'text/html' if json is None else 'application/json')
        self.end_headers()
        if json is not None: self.wfile.write(json)

    def do_PUT(self):
        length = int(self.headers['Content-Length'])
        json = loads(self.rfile.read(length).decode())
        filename = '%s/decrypted-%s' % split(json['Log File'])
        sa_list, error = {}, []
        for spi, value in json['ip xfrm state'].items():
            sa_list[spi] = SecurityAssociation(ESP, spi=int(spi),
                              crypt_algo=value['crypt_algo'], crypt_key=unhexlify(value['crypt_key']),
                              auth_algo=value['auth_algo'], auth_key=unhexlify(value['auth_key']))
        packet = []
        for message in rdpcap(json['Log File']):
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
                    if str(esp.spi) in sa_list:
                        sa = sa_list[str(esp.spi)]
                        try:
                            dec = sa.decrypt(ip)
                        except IPSecIntegrityError as error:
                            error.append('<<<IPSec Integrity Error>>>')                   
                        except Exception as error:
                            error.append(str(error))
                        else:
                            packet.append(dec)
        wrpcap(filename, packet)    
        self.response(201, json=dumps({'Log File': filename, 'error': '\n'.join(error)}).encode())

# ╔══════╗
# ║ main ║
# ╚══════╝
def main():

    BuildDate = date(2023, 8, 25)
    server_address=('127.0.0.1', 9000)
    print('Build Date : %s %s %s\nWeb Server: %s@%s\nUsing CTRL+C to interrupt Web Server' % ((BuildDate.year, month_abbr[BuildDate.month], BuildDate.day) + server_address))
    Handler = HTTPRequestHandler()
    server = HTTPServer(server_address=server_address, RequestHandlerClass=Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close() # Clean-up server (close socket, etc.)

main()
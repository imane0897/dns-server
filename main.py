import socket
from dns_resolve import insert, search, update, query

IP = '127.0.0.1'
PORT = 8123
DNS_CACHE = {}


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print('DNS is listening on {0}:{1} ...'.format(IP, PORT))

    while True:
        data, _ = sock.recvfrom(255)
        domain_name = data.decode('utf-8').strip('\n')
        result = search(DNS_CACHE, domain_name.split('.'))
        if not result:
            result = query(DNS_CACHE, domain_name)
        print(result)


if __name__ == '__main__':
    main()


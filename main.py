import socket
from dns_resolve import insert, search

IP = '127.0.0.1'
PORT = 8123
DNS_CACHE = {}


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print('DNS is listening on {0}:{1} ...'.format(IP, PORT))
    insert(DNS_CACHE, 'test.com'.split('.'), '1.1.1.1')
    insert(DNS_CACHE, 'localhost'.split('.'), '127.0.0.1')
    insert(DNS_CACHE, 'google.com'.split('.'), '172.1.2.3')
    insert(DNS_CACHE, 'test.org'.split('.'), '3.1.2.1')
    print(DNS_CACHE)
    while True:
        data, _ = sock.recvfrom(255)
        print(search(DNS_CACHE, data.decode('utf-8').strip('\n').split('.')))


if __name__ == '__main__':
    main()

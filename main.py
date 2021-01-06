import socket

IP = '127.0.0.1'
PORT = 8123

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))
    print('DNS is listening on {0}:{1} ...'.format(IP, PORT))
    while True:
        data, address = sock.recvfrom(255)
        print(data.decode('utf-8'), address)


if __name__ == '__main__':
    main()

import socket

localhost = "127.0.0.1"
port_KM = 1234
port_B = 1235


def connect_to_server(address, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((address, port))
    return s


def get_file_data():
    f = open("secret.txt", "r+")
    text = f.read()
    f.close()
    return bytes(text, 'utf-8')


def check_file_data(text):
    f = open("dec_secret.txt", "w+")
    f.write(text)
    f.close()


def check_equal():
    f = open("secret.txt", "r")
    g = open("dec_secret.txt", "r")
    a, b = f.read(), g.read()
    f.close()
    g.close()
    return a == b

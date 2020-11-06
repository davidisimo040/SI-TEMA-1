import additional
import socket
import threading
import cripto

mesaj = b"Inceperea realizarii conexiunii intre A si B ..."
list_of_clients = []
MODE = ""
KEY_CBC = b'Davidisimo->tare'
KEY_CFB = b'O iubesc pe Kate'
IV = b'12345678AbCdEfGh'
list_of_nr_blocks = []


def check_B_connection(list_of_clients):
    if len(list_of_clients) == 1:
        return False
    return True


def threaded_client_A(connection):
    global MODE
    connection.send(str.encode('Welcome to the Server Mr. A\nPlease choose between CBC and CFB encryption type: \n'))
    ok_mod_operare = True
    msg1 = ""
    while ok_mod_operare:
        ok_mod_operare = False
        data = connection.recv(2048)
        print("[ CLIENT A ]:  " + data.decode('utf-8'))

        if not check_B_connection(list_of_clients):
            connection.sendall(str.encode("Please Wait For B to connect then choose CBC or CFB encryption mode!\n"))
            ok_mod_operare = True
        else:

            if data.decode('utf-8') == "CBC":
                MODE = "CBC"
                msg1 = "1"

            elif data.decode('utf-8') == "CFB":
                MODE = "CFB"
                msg1 = "2"

            else:
                ok_mod_operare = True
                msg1 = 'Server Says: Wrong MODE entered! Try again choosing between CBC and CFB encryption type: \n'

            if not data:
                break
            connection.sendall(str.encode(str(msg1)))
            if msg1 == "1" or msg1 == "2":
                list_of_clients[1].sendall(str.encode(str(msg1)))

    # send key and iv
    key, iv = cripto.encrypt_k_iv(MODE)
    connection.sendall(key)
    connection.sendall(iv)
    list_of_clients[1].sendall(key)
    list_of_clients[1].sendall(iv)

    key, iv = cripto.decrypt_k_iv(key, iv)
    print(f"[ SERVER ]  mode:  {MODE}  key:  {key.decode('utf-8')}  and  iv:  {iv.decode('utf-8')}\n")

    # receptare mesaj de confirmare

    raspuns = connection.recv(2048)
    print(f"[ CLIENT A *encrypted] {raspuns}")
    if MODE == "CBC":
        raspuns = cripto.decrypt_AES_CBC(raspuns, key, iv)
    else:
        raspuns = cripto.decrypt_AES_CFB(raspuns, key, iv)
    raspuns = raspuns.decode('utf-8')
    print(f"[ CLIENT A *decrypted] {raspuns}")

    # transmitere mesaj inceput comunicatie securizata A <---> B

    for i in range(2):
        list_of_clients[i].sendall(str.encode("Inceput comunicatie intre noduri A <<-->> B"))

    nr_blocks_a = connection.recv(2048)
    nr_blocks_a = nr_blocks_a.decode('utf-8')
    print(f"[ SERVER ] Nr blocks A : {nr_blocks_a}")
    list_of_nr_blocks.append(nr_blocks_a)

    connection.close()


def threaded_client_B(connection):
    connection.send(str.encode(
        'Welcome to the Server Mr. B\nVa rugam asteptati modul de criptare, cheia K a acestuia si vectorul iv...\n'))

    # setare key si pt client B
    iv = IV
    print(MODE)
    # receptare mesaj de confirmare

    raspuns = connection.recv(2048)
    print(f"[ CLIENT B *encrypted] {raspuns}")

    if MODE == "CBC":
        raspuns = cripto.decrypt_AES_CBC(raspuns, KEY_CBC, iv)
    else:
        raspuns = cripto.decrypt_AES_CFB(raspuns, KEY_CFB, iv)
    raspuns = raspuns.decode('utf-8')
    print(f"[ CLIENT B *decrypted] {raspuns}")

    nr_blocks_b = connection.recv(2048)
    nr_blocks_b = nr_blocks_b.decode('utf-8')
    print(f"[ SERVER ] Nr blocks B : {nr_blocks_b}")
    list_of_nr_blocks.append(nr_blocks_b)

    print(f"Fisierul initial coincide cu cel final decriptat:  {additional.check_equal()}")
    print(f"Numarul de blocuri criptate de A este egal cu numarul de blocuri decriptate de B: {compare_nr_blocks(list_of_nr_blocks)}")


def compare_nr_blocks(list_of_nr_blocks):
    return list_of_nr_blocks[0] == list_of_nr_blocks[1]


if __name__ == "__main__":

    ServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        ServerSocket.bind((additional.localhost, additional.port_KM))
    except socket.error as e:
        print(str(e))

    print('Waiting for a Connection..')
    ServerSocket.listen(5)

    client_A, address_A = ServerSocket.accept()
    thread_A = threading.Thread(target=threaded_client_A, args=(client_A,))
    thread_A.start()
    print("[ SERVER ] : S-a conectat A de pe adresa: ", address_A)
    list_of_clients.append(client_A)

    client_B, address_B = ServerSocket.accept()
    thread_B = threading.Thread(target=threaded_client_B, args=(client_B,))
    thread_B.start()
    print("[ SERVER ] : S-a conectat B de pe adresa: ", address_B)
    list_of_clients.append(client_B)

    ServerSocket.close()

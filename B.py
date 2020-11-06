import additional
import cripto
import socket

mesaj = b'Sunt nodul B si confirm primirea cheii si a vectorului!'
MODE = ""

if __name__ == "__main__":
    ok = True
    socketB = additional.connect_to_server(additional.localhost, additional.port_KM)
    # mesaj de intampinare
    response = socketB.recv(2048)
    print(response.decode('utf-8'))
    # mesaj de clarificare mod operare
    response = socketB.recv(1024)
    if response.decode('utf-8') == "1":
        MODE = "CBC"
    elif response.decode('utf-8') == "2":
        MODE = "CFB"

    # receptare key si iv

    key = socketB.recv(2048)
    iv = socketB.recv(2048)
    key, iv = cripto.decrypt_k_iv(key, iv)
    print(f"Modul de criptare ales este: {MODE} , avand cheia: {key.decode('utf-8')}  si iv: {iv.decode('utf-8')}")

    # aici trimitem mesajul de confirmare pt serv KM
    to_be_send = ""
    if MODE == "CFB":
        to_be_send = cripto.encrypt_AES_CFB(mesaj, key, iv)
    else:
        to_be_send = cripto.encrypt_AES_CBC(mesaj, key, iv)
    socketB.send(to_be_send)

    # interceptare mesaj confirmare initializare comunicatie A <<-->> B

    Response = socketB.recv(2048)
    print(f"[ SERVER ] : {Response.decode('utf-8')}")

    # deschidere server B

    socketB_2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        socketB_2.bind((additional.localhost, additional.port_B))
    except socket.error as e:
        print(str(e))
    print("[ SERVER B ] has started!\n")
    print('Waiting for A to connect...')
    socketB_2.listen(1)

    # socketB.send(str.encode("START", 'utf-8'))

    clientA, addressA = socketB_2.accept()
    print("[ SERVER ] : S-a conectat A de pe adresa: ", addressA)

    file_data = clientA.recv(2048)
    decrypted_file = ""
    if MODE == "CBC":
        decrypted_file = cripto.decrypt_AES_CBC(file_data, key, iv)
    else:
        decrypted_file = cripto.decrypt_AES_CFB(file_data, key, iv)
    nr_blocks_decrypted = len(file_data) // 16
    print(f"[ CLIENT B ] Mesajul primit de la A:\n{decrypted_file.decode('utf-8')}")
    additional.check_file_data(decrypted_file.decode('utf-8'))
    socketB.send(bytes(str(nr_blocks_decrypted), 'utf-8'))
    print("Lungimea fisierului decriptat: "+str(len(decrypted_file)))
    print("Numbers of encypted blocks: " + str(nr_blocks_decrypted))
    socketB_2.close()
    socketB.close()

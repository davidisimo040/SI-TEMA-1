import additional
import cripto

mesaj = b'Sunt nodul A si confirm primirea cheii si a vectorului!'

if __name__ == "__main__":
    ok = True
    MODE = ""
    socketA = additional.connect_to_server(additional.localhost, additional.port_KM)
    Response = socketA.recv(2048)
    print(Response.decode('utf-8'))
    while ok:
        Input = input('<Client A>: ')
        socketA.send(str.encode(Input))
        Response = socketA.recv(2048)
        if Response.decode('utf-8') == "1":
            ok = False
            MODE = "CBC"
        elif Response.decode('utf-8') == "2":
            ok = False
            MODE = "CFB"
        else:
            print(Response.decode('utf-8'))
    key = socketA.recv(2048)
    iv = socketA.recv(2048)

    key, iv = cripto.decrypt_k_iv(key, iv)
    print(f"Modul de criptare ales este: {MODE} , avand cheia: {key.decode('utf-8')}  si iv: {iv.decode('utf-8')}")

    # aici trimitem mesajul de confirmare pt serv KM
    to_be_send = ""
    if MODE == "CBC":
        to_be_send = cripto.encrypt_AES_CBC(mesaj, key, iv)
    else:
        to_be_send = cripto.encrypt_AES_CFB(mesaj, key, iv)
    socketA.send(to_be_send)

    # interceptare mesaj confirmare initializare comunicatie A <<-->> B

    Response = socketA.recv(2048)
    print(f"[ SERVER ] : {Response.decode('utf-8')}")

    # conectare server B pt transmitere date

    socket_pt_b = additional.connect_to_server(additional.localhost, additional.port_B)

    # prelucrare fisier si transmitere date

    fisier = additional.get_file_data()
    print("Lungimea fisierului necriptat: "+str(len(fisier)))
    encrypted_file = ""

    if MODE == "CBC":
        encrypted_file = cripto.encrypt_AES_CBC(fisier, key, iv)
    else:
        encrypted_file = cripto.encrypt_AES_CFB(fisier, key, iv)

    socket_pt_b.send(encrypted_file)

    nr_blocks = len(encrypted_file) // 16
    socketA.send(bytes(str(nr_blocks), 'utf-8'))

    print("Numbers of encypted blocks: "+str(len(encrypted_file)//16))
    socket_pt_b.close()
    socketA.close()

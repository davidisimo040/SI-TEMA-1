from Crypto.Cipher import AES

key_K3 = b'Cheie pentru com'  # KEY 3


# functia de padare

def pad(message):
    if len(message) % 16 == 0:
        return message, 0
    if type(message) == str:
        return bytes(message, 'ascii') + b"\0" * (AES.block_size - len(message) % AES.block_size), 1
    else:
        return bytes(message) + b"\0" * (AES.block_size - len(message) % AES.block_size), 1


# functia de unpad

def unpad(message):
    pozitie = message.find(b'\0')
    if pozitie == -1:
        return message
    return message[:pozitie]


def char_xor(sir1, sir2):
    answer = []
    for i in range(16):
        answer.append(sir1[i] ^ sir2[i])
    return answer


# functia de concatenare

def output(multime):
    afisare = []
    for solo_multime in multime:
        for solo_byte in solo_multime:
            afisare.append(solo_byte)
    return bytes(afisare)


# functia de criptare prin modul CBC

def encrypt_AES_CBC(message, key_AES_CBC, iv):
    iv_CBC = list(iv)
    cipher_text = []
    message, ok_pad = pad(message)
    cipher_ECB = AES.new(key_AES_CBC, AES.MODE_ECB)
    for i in range(0, len(message), 16):
        block_data = list(message[i:i + 16])
        block_data = char_xor(block_data, iv_CBC)
        enc_block_data = cipher_ECB.encrypt(bytes(block_data))

        cipher_text.append(enc_block_data)
        iv_CBC = enc_block_data

    return output(cipher_text)


# funtia de decriptare prin modul CBC

def decrypt_AES_CBC(criptat, key_AES_CBC, iv):
    iv_CBC = list(iv)
    plain_text = []
    cipher_ECB = AES.new(key_AES_CBC, AES.MODE_ECB)

    for i in range(0, len(criptat), 16):
        block_data = list(criptat[i:i + 16])
        dec_block_data = cipher_ECB.decrypt(bytes(block_data))
        dec_block_data = char_xor(dec_block_data, iv_CBC)

        plain_text.append(dec_block_data)
        iv_CBC = block_data

    return unpad(output(plain_text))


# functia de criptare prin modul CFB

def encrypt_AES_CFB(message, key_AES_CFB, iv):
    message, ok_pad = pad(message)
    iv_CFB = list(iv)
    cipher_ECB = AES.new(key_AES_CFB, AES.MODE_ECB)
    cipher_text = []

    for i in range(0, len(message), 16):
        block_data = list(message[i:i + 16])
        enc_block_data = char_xor(iv_CFB, block_data)
        enc_block_data = cipher_ECB.encrypt(bytes(enc_block_data))
        cipher_text.append(enc_block_data)
        iv_CFB = enc_block_data
    return output(cipher_text)


# functia de decriptare prin modul CFB

def decrypt_AES_CFB(criptat, key_AES_CFB, iv):
    iv_CFB = list(iv)
    cipher_ECB = AES.new(key_AES_CFB, AES.MODE_ECB)
    plain_text = []

    for i in range(0, len(criptat), 16):
        block_data = list(criptat[i:i + 16])
        dec_block_data = cipher_ECB.decrypt(bytes(block_data))
        dec_block_data = char_xor(dec_block_data, iv_CFB)
        plain_text.append(dec_block_data)
        iv_CFB = block_data
    return unpad(output(plain_text))


# functia de criptare a cheilor si iv de la KM pt A si B

def encrypt_k_iv(mod):

    specific_key = b""
    if mod == "CBC":
        specific_key = b'Davidisimo->tare'
    elif mod == "CFB":
        specific_key = b'O iubesc pe Kate'
    else:
        return 0, 0

    iv = b'12345678AbCdEfGh'

    chiper_ECB = AES.new(key_K3, AES.MODE_ECB)
    return chiper_ECB.encrypt(bytes(specific_key)), chiper_ECB.encrypt(bytes(iv))

# functia de decriptare a cheilor si iv ului criptate

def decrypt_k_iv(key, vec):

    chiper_ECB = AES.new(key_K3, AES.MODE_ECB)
    return chiper_ECB.decrypt(bytes(key)), chiper_ECB.decrypt(bytes(vec))

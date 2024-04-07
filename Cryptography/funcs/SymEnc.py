import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from gmssl import sm4
from utils import convert_to_bytes, generate_key

# AES Encryption
def aes_encrypt(message, len_key, type, key, filepath):
    # type=1:输入密文+自定义密钥 type=2:文件读取密文+自定义密钥 type=3:输入密文+随机密钥 type=4:文件读取密文+随机密钥
    len_key = int(len_key)
    if type == 1:
        # 转换输入信息为byte
        messageToEnc, keyUsed = convert_to_bytes(message), convert_to_bytes(key)
        if len(keyUsed) != len_key:
            return "error_key", "error_key"
    if type == 2:
        # 读取文件内容
        try:
            file = open(filepath,"r")
            message = file.read()
            file.close()
        except:
            return "error_filepath", "error_key"
        # 转换输入信息为byte
        messageToEnc, keyUsed = convert_to_bytes(message), convert_to_bytes(key)
        if len(keyUsed) != len_key:
            return "error_key", "error_key"
    if type == 3:
        keyUsed = generate_key(len_key)
        messageToEnc = convert_to_bytes(message)
        # 指定加密套件的后端，此处使用默
    if type == 4:
        try:
            file = open(filepath,"r")
            message = file.read()
            file.close()
        except:
            return "error_filepath", "error_key"
        keyUsed = generate_key(len_key)
        messageToEnc = convert_to_bytes(message)
    try:
        backend = default_backend()
        # 生成一个长度为16Byte的随机字符串，此时AES密钥长度为128bit
        iv = os.urandom(16)
        # 创建一个Cipher对象，该对象使用AES算法和CFB模式。将密钥转换为字节类型，这里相当于创建了一个加密器
        cipher = Cipher(algorithms.AES(keyUsed), modes.CFB(iv), backend=backend)
        # 调库加密
        encryptor = cipher.encryptor()
        # 这行代码创建了一个PKCS7填充器，填充器的块大小为128。
        # 加密后的数据长度必须为128的倍数，因此使用PKCS7填充器可以确保数据的长度符合要求
        padder = padding.PKCS7(128).padder()
        # 填充数据，保证总长度为128bit的整数倍
        padded_data = padder.update(messageToEnc) + padder.finalize()
        # 进行加密
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        aes_dict = {"ciphertext":base64.b64encode(iv + encrypted_data).decode(),"key":keyUsed.decode()}
        
        return aes_dict
    except:
        return "encrypt_error", "error_key"
    

# AES Decryption
def aes_decrypt(ciphertext,key, len_key):
    len_key = int(len_key)
    keyUsed = convert_to_bytes(key)
    print(len(keyUsed))
    if len(keyUsed) != len_key//8:
        return "密钥长度错误，请重新输入"
    
    backend = default_backend()
    ciphertext = base64.b64decode(ciphertext.encode())
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(keyUsed), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    aes_dict = {"message":unpadded_data.decode()}
    return aes_dict
    

def Camellia_encrypt(message, len_key, type, key, filepath):

    # type=1:输入密文+自定义密钥 type=2:文件读取密文+自定义密钥 type=3:输入密文+随机密钥 type=4:文件读取密文+随机密钥
    len_key = int(len_key)
    if type == 1:
        # 转换输入信息为byte
        messageToEnc, keyUsed = convert_to_bytes(message), convert_to_bytes(key)
        if len(keyUsed) != len_key:
            return "error_key", "error_key"
    if type == 2:
        # 读取文件内容
        try:
            file = open(filepath,"r")
            message = file.read()
            file.close()
        except:
            return "error_filepath", "error_key"
        # 转换输入信息为byte
        messageToEnc, keyUsed = convert_to_bytes(message), convert_to_bytes(key)
        if len(keyUsed) != len_key:
            return "error_key", "error_key"
    if type == 3:
        keyUsed = generate_key(len_key)
        messageToEnc = convert_to_bytes(message)
        # 指定加密套件的后端，此处使用默
    if type == 4:
        try:
            file = open(filepath,"r")
            message = file.read()
            file.close()
        except:
            return "error_filepath", "error_key"
        keyUsed = generate_key(len_key)
        messageToEnc = convert_to_bytes(message)
    try:
        backend = default_backend()
        # 生成一个长度为16Byte的随机字符串，此时AES密钥长度为128bit
        iv = os.urandom(16)
        # 创建一个Cipher对象，该对象使用AES算法和CFB模式。将密钥转换为字节类型，这里相当于创建了一个加密器
        cipher = Cipher(algorithms.Camellia(keyUsed), modes.CFB(iv), backend=backend)
        # 调库加密
        encryptor = cipher.encryptor()
        # 这行代码创建了一个PKCS7填充器，填充器的块大小为128。
        # 加密后的数据长度必须为128的倍数，因此使用PKCS7填充器可以确保数据的长度符合要求
        padder = padding.PKCS7(128).padder()
        # 填充数据，保证总长度为128bit的整数倍
        padded_data = padder.update(messageToEnc) + padder.finalize()
        # 进行加密
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        Camellia_dict = {"ciphertext":base64.b64encode(iv + encrypted_data).decode(),"key":keyUsed.decode()}
        return Camellia_dict
        
    except:
        return "encrypt_error", "error_key"

def Camellia_decrypt(ciphertext,key, len_key):
    len_key = int(len_key)
    keyUsed = convert_to_bytes(key)
    print(len(keyUsed))
    if len(keyUsed) != len_key // 8:
        return "密钥长度错误，请重新输入"
    
    backend = default_backend()
    ciphertext = base64.b64decode(ciphertext.encode())
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.Camellia(keyUsed), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    Camellia_dict = {"message":unpadded_data.decode()}
    return Camellia_dict


# message = "I'm a message~"
# len_key = 128
# type = 3
# key = ""
# filepath = ""
# result = Camellia_encrypt(message, len_key, type, key, filepath)
# print(result["ciphertext"])
# print(result["key"])

def ChaCha20Poly1305_encrypt(message,type, key, filepath):
    if type == 1:
        # 转换输入信息为byte
        messageToEnc, keyUsed = convert_to_bytes(message), convert_to_bytes(key)
        if len(keyUsed) != 256:
            return "error_key", "error_key"
    if type == 2:
        # 读取文件内容
        try:
            file = open(filepath,"r")
            message = file.read()
            file.close()
        except:
            return "error_filepath", "error_key"
        # 转换输入信息为byte
        messageToEnc, keyUsed = convert_to_bytes(message), convert_to_bytes(key)
        if len(keyUsed) != 256:
            return "error_key", "error_key"
    if type == 3:
        keyUsed = generate_key(256)
        messageToEnc = convert_to_bytes(message)
        # 指定加密套件的后端，此处使用默
    if type == 4:
        try:
            file = open(filepath,"r")
            message = file.read()
            file.close()
        except:
            return "error_filepath", "error_key"
        keyUsed = generate_key(256)
        messageToEnc = convert_to_bytes(message)
    
    
    chacha = ChaCha20Poly1305(keyUsed)
    # 96位新鲜数
    nonce = generate_key(96)
    ciphertext = chacha.encrypt(nonce, messageToEnc,None)
    
    ChaCha_dict = {"ciphertext":base64.b64encode(nonce + ciphertext).decode(), "key":keyUsed.decode(), "nonce":nonce.decode()}
    return ChaCha_dict
    

def ChaCha20Poly1305_decrypt(ciphertext,key,nonce):
    keyUsed = convert_to_bytes(key)
    print(len(keyUsed))
    if len(keyUsed) != 32:
        return "error_key"
    ciphertext = convert_to_bytes(ciphertext)
    chacha = ChaCha20Poly1305(keyUsed)
    ciphertext = base64.b64decode(ciphertext)[12:]
    decrypted_data = chacha.decrypt(nonce.encode(), ciphertext, None)
    
    ChaCha_dict = {"message":decrypted_data.decode()}
    return ChaCha_dict

def SM4_encrypt(message,type, key, filepath):
    # type=1:输入密文+自定义密钥 type=2:文件读取密文+自定义密钥 type=3:输入密文+随机密钥 type=4:文件读取密文+随机密钥
    if type == 1:
        # 转换输入信息为byte
        messageToEnc, keyUsed = convert_to_bytes(message), convert_to_bytes(key)
        if len(keyUsed) != 16:
            return "error_key", "error_key"
    if type == 2:
        # 读取文件内容
        try:
            file = open(filepath,"r")
            message = file.read()
            file.close()
        except:
            return "error_filepath", "error_key"
        # 转换输入信息为byte
        messageToEnc, keyUsed = convert_to_bytes(message), convert_to_bytes(key)
        if len(keyUsed) != 16:
            return "error_key", "error_key"
    if type == 3:
        keyUsed = generate_key(128)
        messageToEnc = convert_to_bytes(message)
        # 指定加密套件的后端，此处使用默
    if type == 4:
        try:
            file = open(filepath,"r")
            message = file.read()
            file.close()
        except:
            return "error_filepath", "error_key"
        keyUsed = generate_key(128)
        messageToEnc = convert_to_bytes(message)
    
    sm4Alg = sm4.CryptSM4()  # 实例化sm4
    sm4Alg.set_key(keyUsed, sm4.SM4_ENCRYPT)
    
    enRes = sm4Alg.crypt_ecb(messageToEnc)  # 开始加密,bytes类型，ecb模式
    
    SM4_dict = {"ciphertext":base64.b64encode(enRes).decode(),"key":keyUsed.decode()}
    return SM4_dict
    

def SM4_decrypt(ciphertext,key):
    keyUsed = convert_to_bytes(key)
    ciphertext = convert_to_bytes(ciphertext)
    if len(keyUsed) != 16:
        return "error_key"
    
    sm4Alg = sm4.CryptSM4()  # 实例化sm4
    sm4Alg.set_key(keyUsed, sm4.SM4_DECRYPT)  # 设置密钥
    deRes = sm4Alg.crypt_ecb(base64.b64decode(ciphertext))
    
    SM4_dict = {"message":deRes.decode()}
    return SM4_dict

res = SM4_encrypt("I'm message",3,"","")
print(res["ciphertext"])
print(res["key"])
res = SM4_decrypt(res["ciphertext"],res["key"])
print(res["message"])


import asyncio
import websockets
import threading
import time
import json
from scapy.all import *
import snmp_cmds


import os
import base64
from cryptography.hazmat.primitives import hashes, cmac, hmac, poly1305, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ed448
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from blind_watermark import WaterMark
from datetime import datetime
from PIL import Image
from gmssl import sm4
import base64
from pysnmp.hlapi import *
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv


# ----------------------------------------------------------------

# CONSOLE FOR TESTING

# ----------------------------------------------------------------

# 单一模块测试用开关
SNIFFER_AVAILABLE = True
STATE_MONITOR_AVAILABLE = True
SNMP_AVAILABLE =True

# ----------------------------------------------------------------

# GLOBAL VARIALBES

# ----------------------------------------------------------------

# 对应功能是否开启标识符
sniffing = [True]
state_monitoring=[True]
snmping=[True]
des_ip=["192.168.200.128"]
sniffer_iface = "ens33"  # 默认接口
buff_sniffer = []  # 全局变量
buff_snmp = []  # 全局变量
buff_state = []  # 全局变量
sent=[0]
serial=[0]
TIMEOUT = 100
trap_info = {"1.3.6.1.2.1.1.3.0": "",
			 "1.3.6.1.6.3.1.1.4.1.0": "",
			 "1.3.6.1.6.3.18.1.3.0": "",
			 "1.3.6.1.6.3.18.1.4.0": "",
			 "1.3.6.1.6.3.1.1.4.3.0": ""}







# ----------------------------------------------------------------

# CRYPT FUNCTIONS

# ----------------------------------------------------------------
def generate_key(length):
    # 生成随机字节串
    characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
    key = ''.join(random.choices(characters, k=length//8))
    return key.encode()
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


def RSA_encrypt(message, len_secret_key):
    len_secret_key = int(len_secret_key)
    if len_secret_key not in [512, 1024, 2048, 4096]:
        raise ValueError("Invalid secret_key length !")
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=len_secret_key)
    public_key = private_key.public_key()
    
    messageToEncrypt = convert_to_bytes(message)
    ciphertext = public_key.encrypt(
    messageToEncrypt,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    RSA_dict = {"ciphertext":base64.b64encode(ciphertext).decode(),"pubKey":public_pem.decode(),"priKey":private_pem.decode()}
    return RSA_dict
    
    # return base64.b64encode(ciphertext).decode(), public_key, private_key

def RSA_decrypt(ciphertext, private_pem):
    ciphertext = base64.b64decode(ciphertext.encode())
    private_key = private_pem.encode()
    private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    print(private_key.key_size)
    print(len(ciphertext))
    
    decrypted_data = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
    
    RSA_dict = {"message":decrypted_data.decode()}
    return RSA_dict
    
    # return decrypted_data.decode()


def generate_RSA_keys(len_secret_key):
    len_secret_key = int(len_secret_key)
    if len_secret_key not in [512, 1024, 2048, 4096]:
        raise ValueError("Invalid secret_key length !")
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=len_secret_key)
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    RSA_dict = {"pubKey":public_pem.decode(),"priKey":private_pem.decode()}
    return RSA_dict
    
    # return public_key, private_key


def generate_Ed25519_keys():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    Ed25519_dict = {"pubKey":public_pem.decode(),"priKey":private_pem.decode()}
    return Ed25519_dict
    
    # return public_key, private_key

def generate_Ed448_keys():
    private_key = ed448.Ed448PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    Ed448_dict = {"pubKey":public_pem.decode(),"priKey":private_pem.decode()}
    return Ed448_dict
    
    # return public_key, private_key
    

def Ed448_Sig(message):
    private_key = ed448.Ed448PrivateKey.generate()
    public_key = private_key.public_key()
    messageToEncrypt = message.encode()
    signature = private_key.sign(messageToEncrypt)
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    Ed448_dict = {"ciphertext":base64.b64encode(signature).decode(),"pubKey":public_pem.decode(),"priKey":private_pem.decode()}
    return Ed448_dict
    
    # return base64.b64encode(signature).decode(), public_key, private_key

def Ed448_Verify(message, signature, public_pem):
    try:
        signature = base64.b64decode(signature.encode())

        messageToEnc = message.encode()
        public_pem = public_pem.encode()
        
        public_key = serialization.load_pem_public_key(public_pem, default_backend())

        # Verify the signature
        public_key.verify(signature, messageToEnc)
        # If the verification is successful, return True
        
        res_dict = {"res":True}
        return res_dict
        
        # return True
    except:
        # If the verification fails, return False
        res_dict = {"res":False}
        return res_dict
    
        # return False

# 消息认证码
def CMAC_en(message, len_key):
    len_key = int(len_key)
    if len_key not in [128, 192, 256]:
        raise ValueError("Invalid key size. Key size must be 128, 192, or 256.")
    key = generate_key(len_key)
    messageToEncrypt = message.encode()
    
    c = cmac.CMAC(algorithms.AES(key))
    c.update(messageToEncrypt)
    # 生成认证码
    tag = c.finalize()
    
    CMAC_dict = {"MAC":base64.b64encode(tag).decode(), "key":key.decode()}
    return CMAC_dict
    
    # return base64.b64encode(tag).decode(), key

def CMAC_de(message, key, tag):
    key = key.encode()
    c = cmac.CMAC(algorithms.AES(key))
    c.update(message.encode())
    
    try:
        c.verify(base64.b64decode(tag.encode()))
        
        res_dict = {"res":True}
        return res_dict
        # return True
    except:
        res_dict = {"res":False}
        return res_dict
        # return False

def HMAC_en(message):
    key = generate_key(256)
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message.encode())
    tag = h.finalize()
    
    HMAC_dict = {"MAC":base64.b64encode(tag).decode(), "key":key.decode()}
    return HMAC_dict
    
    # return base64.b64encode(tag).decode(), key

def HMAC_de(message, key, tag):
    key = key.encode()
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message.encode())
    
    try:
        h.verify(base64.b64decode(tag.encode()))
        res_dict = {"res":True}
        return res_dict
        # return True
    except:
        res_dict = {"res":False}
        return res_dict
        # return False

def poly1305_en(message):
    key = generate_key(256)
    p = poly1305.Poly1305(key)
    p.update(message.encode())
    tag = p.finalize()
    
    poly_dict = {"MAC":base64.b64encode(tag).decode(), "key":key.decode()}
    return poly_dict
    
    # return base64.b64encode(tag).decode(), key

def poly1305_de(message, key, tag):
    key = key.encode()
    p = poly1305.Poly1305(key)
    p.update(message.encode())
    try:
        p.verify(base64.b64decode(tag.encode()))
        res_dict = {"res":True}
        return res_dict
        # return True
    except:
        res_dict = {"res":False}
        return res_dict
        # return False

def SHA_family(message, type_sha):
    sha_types = {
        "SHA-224": hashes.SHA224,
        "SHA-256": hashes.SHA256,
        "SHA-384": hashes.SHA384,
        "SHA-512": hashes.SHA512,
        "SHA3-224": hashes.SHA3_224,
        "SHA3-256": hashes.SHA3_256,
        "SHA3-384": hashes.SHA3_384,
        "SHA3-512": hashes.SHA3_512,
    }

    if type_sha in sha_types:
        digest = hashes.Hash(sha_types[type_sha](), backend=default_backend())
        digest.update(message.encode())
        SHA_dict = {"hash":base64.b64encode(digest.finalize()).decode()}
        return SHA_dict
        # return base64.b64encode(digest.finalize()).decode()
    else:
        raise ValueError(f"Invalid SHA type: {type_sha}")
    
def Shake_family(message, len_output, type_shake):
    len_output = int(len_output)
    if len_output < 128 or len_output > 8192:
        raise ValueError("The length of output must be between 128 and 8192 bits.")
    message = message.encode()
    if type_shake == "SHAKE128":
        digest = hashes.Hash(hashes.SHAKE128(len_output), backend=default_backend())
    elif type_shake == "SHAKE256":
        digest = hashes.Hash(hashes.SHAKE256(len_output), backend=default_backend())
    else :
        raise ValueError("Invalid SHAKE type.")
    digest.update(message)
    SHAKE_dict = {"hash":base64.b64encode(digest.finalize()).decode()}
    return SHAKE_dict
    # return base64.b64encode(digest.finalize()).decode()

def embed_text(image_path, text, output_path):
	image_path = utils.convert_slashes(image_path)
	print("image_path:", image_path)
	output_path = utils.convert_slashes(output_path)
	# print("output_path:",output_path)
	# 初始化嵌入器
	bwm1 = WaterMark(password_img=1, password_wm=1)
	# 获取待嵌入水印图片路径
	bwm1.read_img(image_path)
	# 获取待嵌入文字
	watermark = text
	# 读取
	bwm1.read_wm(watermark, mode='str')
	# 嵌入
	now = datetime.now()
	time_string = now.strftime("%Y%m%d_%H%M%S_")
	len_wm = len(bwm1.wm_bit)
	output_path = output_path + '/' + time_string + str(len_wm) + "_embedded.png"
	print("output_path:", output_path)
	# output_path = './output/embedded.png'
	bwm1.embed(output_path)
	
	len_wm = len(bwm1.wm_bit)
	print('Put down the length of wm_bit {len_wm}'.format(len_wm=len_wm))
	
	res_dict = {"len_wm": len_wm, "output_path": output_path}
	return res_dict


# return len_wm, output_path

def get_text(image_path, len_wm, output_path):
	bwm1 = WaterMark(password_img=1, password_wm=1)
	wm_extract = bwm1.extract(image_path, wm_shape=int(len_wm), mode='str')
	
	now = datetime.now()
	time_string = now.strftime("%Y%m%d_%H%M%S_")
	output_path = output_path + '/' + time_string + str(len_wm) + "_extracted.txt"
	with open(output_path, 'w') as f:
		f.write(wm_extract)
	
	res_dict = {"wm_extract": wm_extract}
	return res_dict


# return wm_extract

def embed_img(img_path, wm_path, output_path):
	img_path = utils.convert_slashes(img_path)
	wm_path = utils.convert_slashes(wm_path)
	output_path = utils.convert_slashes(output_path)
	
	bwm1 = WaterMark(password_wm=1, password_img=1)
	# read original image
	bwm1.read_img(img_path)
	# read watermark
	bwm1.read_wm(wm_path)
	# embed
	now = datetime.now()
	time_string = now.strftime("%Y%m%d_%H%M%S_")
	img = Image.open(wm_path)
	width, height = img.size
	output_path = output_path + '/' + time_string + str(width) + '_' + str(height) + "_embedded.png"
	
	bwm1.embed(output_path)
	res_dict = {"output_path": output_path, "width": width, "height": height}
	return res_dict


# return output_path, width, height

def get_img(image_path, output_path, width, height):
	image_path = utils.convert_slashes(image_path)
	output_path = utils.convert_slashes(output_path)
	bwm1 = WaterMark(password_wm=1, password_img=1)
	# notice that wm_shape is necessary
	now = datetime.now()
	time_string = now.strftime("%Y%m%d_%H%M%S_")
	output_path = output_path + '/' + time_string + str(width) + '_' + str(height) + "_wm.png"
	bwm1.extract(filename=image_path, wm_shape=(height, width), out_wm_name=output_path, )
	res_dict = {"output_path": output_path}
	return res_dict
# return output_path
def convert_to_bytes(data):
    if isinstance(data, bytes):  # 如果数据已经是字节流，直接返回
        return data
    elif isinstance(data, str):  # 如果数据是字符串，使用utf-8编码转换为字节流
        return data.encode('utf-8')
    elif isinstance(data, int):  # 如果数据是整数（比特流），使用to_bytes方法转换为字节流
        return (data).to_bytes((data.bit_length() + 7) // 8, 'big' or data == 0)
    elif isinstance(data, str):  # 如果数据是十六进制字符串，使用bytes.fromhex方法转换为字节流
        return bytes.fromhex(data)
    else:
        raise TypeError('Unsupported data type')
def convert_slashes(file_path):
    return file_path.replace('\\', '/')










# ----------------------------------------------------------------

# SNIFFER FUNCTIONS

# ----------------------------------------------------------------

def print_packet_info(packet_dict):
    print(packet_dict)

def sniff_packets():
    while True:
        sniff(iface=sniffer_iface, prn=sniffer_packet_callback, filter="ip or arp or ip6", store=0, count=10)
        time.sleep(0.055)

def sniffer_packet_callback(packet):
    # 创建一个字典来存储数据包信息
    packet_dict = {}

    # 获取数据包的时间戳
    packet_dict['time'] = packet.time

    # 处理IPv6数据包
    if IPv6 in packet:
        packet_dict['src'] = packet[IPv6].src
        packet_dict['dst'] = packet[IPv6].dst
        packet_dict['protocol'] = 'IPv6'
        packet_dict['info'] = packet[IPv6].show2(dump=True)

    # 处理IPv4数据包
    elif IP in packet:
        packet_dict['src'] = packet[IP].src
        packet_dict['dst'] = packet[IP].dst
        packet_dict['protocol'] = 'IP'
        packet_dict['info'] = packet[IP].show2(dump=True)

        if TCP in packet:
            packet_dict['protocol'] = 'TCP'
            packet_dict['info'] += packet[TCP].show2(dump=True)
        elif UDP in packet:
            packet_dict['protocol'] = 'UDP'
            packet_dict['info'] += packet[UDP].show2(dump=True)
        elif ICMP in packet:
            packet_dict['protocol'] = 'ICMP'
            packet_dict['info'] += packet[ICMP].show2(dump=True)

    # 处理ARP数据包
    elif ARP in packet:
        packet_dict['src'] = packet[ARP].psrc
        packet_dict['dst'] = packet[ARP].pdst
        packet_dict['protocol'] = 'ARP'
        packet_dict['info'] = packet[ARP].show2(dump=True)

    # 使用send函数发送数据包信息
    sniffer_send(packet_dict)

    # 打印数据包信息
    print_packet_info(packet_dict)


    
    
    

    
    
    
# ----------------------------------------------------------------

# SNMP FUNCTIONS

# ----------------------------------------------------------------

def GetByOid(des_ip, oid):
	try:
		res = snmp_cmds.snmpwalk(des_ip, oid, 'public', 161, TIMEOUT)
		get_dict = {"oid":res[0][0],"value":res[0][1]}
		return get_dict
		# return [varBind for varBind in res]
	except:
		return "connect error"

def SetByOid(des_ip, oid, value, type):
	try:
		types = {"integer": 'i',
				 "unsigned_integer": 'u',
				 "time_ticks": 't',
				 "ip_address": 'a',
				 "object_identifier": 'o',
				 "string": 's',
				 "hex_string": 'x',
				 "decimal_string": 'd',
				 "bit_string": 'b'}
		type_index = types[type]
		res = snmp_cmds.snmpset(des_ip, oid, type_index, value, 'public', 161, TIMEOUT)
		return res
	except:
		return "NoChangable!"

def sendTrap(des_ip, oid, oid_extra, value):
	try:
		# sendNotification函数用来发送SNMP消息，包括trap和inform
		errorIndication, errorStatus, errorIndex, varBinds = next(
			sendNotification(
				SnmpEngine(),
				CommunityData('public'),
				UdpTransportTarget((des_ip, 162)),
				ContextData(),
				'trap',
				NotificationType(
					ObjectIdentity(oid)
				).addVarBinds(
					(oid_extra, OctetString(value))
				)
			)
		)
		
		if errorIndication:
			print('Notification not sent: %s' % errorIndication)
			return errorStatus, errorIndex
	except:
		return "send error"

def monitor_cpu(des_ip):
	try:
		res = snmp_cmds.snmpwalk(des_ip, '.1.3.6.1.4.1.2021.11.11.0', 'public', 161, TIMEOUT)
		return 100 - int(res[0][1])
	except:
		return "connect error"

def monitor_RAM(des_ip):
    # 获取内存使用量
    res1 = GetByOid(des_ip, '.1.3.6.1.4.1.2021.4.6.0')
    if isinstance(res1, str):
       return "get memory error"
    # 获取内存总量
    res2 = GetByOid(des_ip, '.1.3.6.1.4.1.2021.4.5.0')
    if isinstance(res2, str):
        return "get memory error"
    # 计算内存利用率
    if isinstance(res1, str) or isinstance(res2, str):
        return "calculate error"
    else:

        res1_value = float(res1["value"].replace(' kB', ''))
        res2_value = float(res2["value"].replace(' kB', ''))
        return res1_value / res2_value

def monitor_disk(des_ip):
	# 获取所有分区的总容量
	total_space = 0
	res1 = snmp_cmds.snmpwalk(des_ip, '.1.3.6.1.2.1.25.2.3.1.5',"public",161,TIMEOUT)
	if isinstance(res1, str):
		return "connect error"
	else:
		for varBind in res1:
			total_space += float(varBind[1].replace(' kB', ''))
	
	# 获取所有分区的总使用量
	total_used = 0
	res2 = snmp_cmds.snmpwalk(des_ip, '.1.3.6.1.2.1.25.2.3.1.6',"public",161,TIMEOUT)
	if isinstance(res2, str):
		return "connect error"
	else:
		for varBind in res2:
			total_used += float(varBind[1].replace(' kB', ''))
	
	# 计算磁盘使用率
	if isinstance(res1, str) or isinstance(res2, str):
		return "calculate error"
	else:
		return total_used / total_space

def monitor_MAC(des_ip):
	# MAC地址
	res = GetByOid(des_ip, '.1.3.6.1.2.1.2.2.1.6')
	if isinstance(res, str):
		return "connect error"
	else:
		return res

def get_bytes(ip, oid):
	try:
		results = snmp_cmds.snmpwalk(ip, oid, 'public', 161, 2)
		total_bytes = sum(int(result[1]) for result in results)
		return total_bytes
	except:
		return "Connection error"

def monitor_net(des_ip):
	# 获取初始的发送和接收字节数
	initial_received_bytes = get_bytes(des_ip, '.1.3.6.1.2.1.2.2.1.10')
	initial_sent_bytes = get_bytes(des_ip, '.1.3.6.1.2.1.2.2.1.16')
	
	# 等待一段时间（例如5分钟）
	time.sleep(2)
	
	# 获取5分钟后的发送和接收字节数
	final_received_bytes = get_bytes(des_ip, '.1.3.6.1.2.1.2.2.1.10')
	final_sent_bytes = get_bytes(des_ip, '.1.3.6.1.2.1.2.2.1.16')
	
	# 计算网络流量
	if isinstance(initial_received_bytes, str) or isinstance(final_received_bytes, str):
		return "Error calculating received traffic"
	else:
		received_traffic = final_received_bytes - initial_received_bytes
	
	if isinstance(initial_sent_bytes, str) or isinstance(final_sent_bytes, str):
		return "Error calculating sent traffic"
	else:
		sent_traffic = final_sent_bytes - initial_sent_bytes
	
	if not isinstance(received_traffic, str) and not isinstance(sent_traffic, str):
		total_traffic = received_traffic + sent_traffic
	
	return received_traffic, sent_traffic, total_traffic

def warn_cpu(des_ip, warn_level):
	warn_level = int(warn_level)
	res = monitor_cpu(des_ip)
	if int(res) > warn_level:
		return False
	time.sleep(1)
	return True

def warn_memory(des_ip, warn_level):
	warn_level = int(warn_level)

	res = monitor_RAM(des_ip)
	if res > warn_level:
		return False
	time.sleep(1)
	return True

def warn_disk(des_ip, warn_level):
	warn_level = int(warn_level)

	res = monitor_disk(des_ip)
	if res > warn_level:
		return False
	time.sleep(1)
	return True

def start_monitor_state():
	
	while True:
		des_ip_=des_ip[0]
		if state_monitoring[0]==False:
			continue
		try:
			cpu_state = monitor_cpu(des_ip_)
			RAM_state = monitor_RAM(des_ip_)

			disk_state = monitor_disk(des_ip_)
			download_state, upload_state, total_state = monitor_net(des_ip_)
			state_packet = {"cpu_state":cpu_state, "RAM_state":RAM_state, "disk_state":disk_state,
							"download_state":download_state, "upload_state":upload_state, "total_state":total_state}
			print(state_packet)
			print(des_ip_)
			state_packet_send(state_packet)
		except:
			raise ValueError("ip wrong!")
		
		time.sleep(3)

class TrapListener:
	def __init__(self):
		self.trap_info = {
            "1.3.6.1.2.1.1.3.0": "",		# 超时时间
            "1.3.6.1.6.3.1.1.4.1.0": "",	# trapOid
            "1.3.6.1.6.3.18.1.3.0": "",		# IP
            "1.3.6.1.6.3.18.1.4.0": "",		# community
            "1.3.6.1.6.3.1.1.4.3.0": ""		# trapType
        }
		self.snmpEngine = SnmpEngine()

	def cbFun(self, snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
		for name, val in varBinds:
			self.trap_info[name.prettyPrint()] = val.prettyPrint()
		trap_packet_send(self.trap_info)
        
	def listenTrap(self):
		config.addTransport(
			self.snmpEngine,
			udp.domainName,
			udp.UdpTransport().openServerMode(('0.0.0.0', 162))
		)
		config.addV1System(self.snmpEngine, 'my-area', 'public')
		ntfrcv.NotificationReceiver(self.snmpEngine, self.cbFun)
		self.snmpEngine.transportDispatcher.jobStarted(1)
		try:
			self.snmpEngine.transportDispatcher.runDispatcher()
		except:
			self.snmpEngine.transportDispatcher.closeDispatcher()
			raise
	
	def getTrapInfo(self):
		return self.trap_info













# ----------------------------------------------------------------

# FUNCTION FOR SERVER RUNNING

# ----------------------------------------------------------------

def send_message_sniffer(message,source,message_type):
    package={
        "source":source,
        "message_type":message_type,
        "message":message
    }
    buff_sniffer.append(package)
    serial[0]+=1

def send_message_state(message,source,message_type):
    package={
        "source":source,
        "message_type":message_type,
        "message":message
    }
    buff_state.append(package)
    serial[0]+=1
def send_message_snmp(message,source,message_type):
    package={
        "source":source,
        "message_type":message_type,
        "message":message

    }
    buff_snmp.append(package)
    serial[0]+=1


def sniffer_send(packet_dict):
    if SNIFFER_AVAILABLE and sniffing[0]:
    	send_message_sniffer(message=packet_dict,source="sniffer",message_type="server_speak")

def trap_packet_send(packet_dict):
    if SNMP_AVAILABLE and snmping[0]:
        send_message_snmp(message=packet_dict,source="trap_packet",message_type="server_speak")


def state_packet_send(packet_dict):
    if STATE_MONITOR_AVAILABLE and state_monitoring[0]:
    	send_message_state(message=packet_dict,source="state_monitor",message_type="server_speak")

async def echo(websocket, path):
    async def recv():
        while True:
            message = await websocket.recv()  # 监听js传来的信息
            data = json.loads(message)
            reply=dict_analysis(data)
            await websocket.send(json.dumps(reply))
            print(data["type"])
            print(f"< {message}")  # print出来

    async def send():
        while True:
            if buff_sniffer and sniffing[0] :
                message = buff_sniffer.pop(-1)  # 如果buff_sniffer不为空，取出第一个元素
                await websocket.send(json.dumps(message))  # 通过websocket传给js
                sent[0]+=1
            if buff_snmp and snmping[0] :
                message = buff_snmp.pop(-1)  # 如果buff不为空，取出第一个元素
                await websocket.send(json.dumps(message))  # 通过websocket传给js
                sent[0]+=1    
            if buff_state and state_monitoring[0] :
                message = buff_state.pop(-1)  # 如果buff不为空，取出第一个元素
                await websocket.send(json.dumps(message))  # 通过websocket传给js
                sent[0]+=1    
            await asyncio.sleep(0.05)

    recv_task = asyncio.ensure_future(recv())
    send_task = asyncio.ensure_future(send())
    done, pending = await asyncio.wait(
        [recv_task, send_task],
        return_when=asyncio.FIRST_COMPLETED,
    )

    for task in pending:
        task.cancel()









# ----------------------------------------------------------------

# OPERATE FUNCTION TO THE PACKAGES IN COMMUNICATIING WITH FRONT PART

# ----------------------------------------------------------------

def dict_analysis(dict):
    message=""
    package={}

    if dict["source"]=="sniffer":
        if dict["type"]=="start":
            message="sniffer_start"
            sniffing[0]=True
            print(message)
        elif dict["type"]=="stop":
            message="sniffer_stop"
            sniffing[0]=False
            print(message)
    elif dict["source"]=="crypt":
        content=dict["content"]
        if dict["type"]=="RSA_encrypt":
            mes=content["message"]
            message="RSA_encrypt_result"
            len_secret_key=content["len_secret_key"]
            package=RSA_encrypt(mes, len_secret_key)
        elif dict["type"]=="RSA_decrypt":
            mes=content["message"]
            message="RSA_decrypt_result"
            len_secret_key=content["len_secret_key"]
            package=RSA_decrypt(mes, len_secret_key)
            
            
        elif dict["type"]=="generate_RSA_keys":
            mes=content["message"]
            message="generate_RSA_keys_result"
            len_secret_key=content["len_secret_key"]
            package=generate_RSA_keys(len_secret_key)
            
            
        elif dict["type"]=="generate_Ed25519_keys":
            mes=content["message"]
            message="generate_Ed25519_keys_result"
            package=generate_Ed25519_keys()    
        elif dict["type"]=="generate_Ed448_keys":
            mes=content["message"]
            message="generate_Ed448_keys_result"
            package=generate_Ed448_keys() 
            
            
        elif dict["type"]=="Camellia_encrypt_keys":
            mes=content["message"]
            message="Camellia_encrypt_keys_result"
            len_key=content["len_key"]
            tp=content["type"]
            key=content["key"]
            filepath=content["filepath"]
            package=Camellia_encrypt(mes, len_key, tp, key, filepath)    
        elif dict["type"]=="Camellia_decrypt_keys":
            ciphertext=content["ciphertext"]
            message="Camellia_decrypt_keys_result"
            len_key=content["len_key"]
            key=content["key"]
            package=Camellia_decrypt(ciphertext,key, len_key) 
            
                 
        elif dict["type"]=="ChaCha20Poly1305_encrypt":
            mes=content["message"]
            message="ChaCha20Poly1305_encrypt_result"
            tp=content["type"]
            key=content["key"]
            filepath=content["filepath"]
            package=ChaCha20Poly1305_encrypt(mes, tp, key, filepath)   
        elif dict["type"]=="ChaCha20Poly1305_decrypt":
            ciphertext=content["ciphertext"]
            key=content["key"]
            nonce=content["nonce"]
            package=ChaCha20Poly1305_decrypt(ciphertext,key,nonce)  
            
            
        elif dict["type"]=="SM4_encrypt":
            mes=content["message"]
            message="SM4_encrypt_result"
            tp=content["type"]
            key=content["key"]
            filepath=content["filepath"]
            package=SM4_encrypt(mes,tp, key, filepath)  
        elif dict["type"]=="SM4_decrypt":
            ciphertext=content["ciphertext"]
            message="SM4_decrypt_result"
            key=content["key"]
            package=SM4_decrypt(ciphertext,key)  
            
              
        elif dict["type"]=="Ed448_Sig":
            mes=content["message"]
            message="Ed448_Sig_result"
            package=Ed448_Sig(mes) 
        elif dict["type"]=="Ed448_Verify":
            mes=content["message"]
            public_pem=content["public_pem"]
            signature=content["signature"]
            message="Ed448_Verify_result"
            package=Ed448_Verify(mes, signature, public_pem)
        
        
        elif dict["type"]=="CMAC_en_Verify":
            mes=content["message"]
            len_key=content["len_key"]
            message="CMAC_en_result"
            package=CMAC_en(mes, len_key)    
        elif dict["type"]=="CMAC_de":
            mes=content["message"]
            key=content["key"]
            tag=content["tag"]
            message="CMAC_de_result"
            package=CMAC_de(mes, key, tag)  
        
        
        elif dict["type"]=="HMAC_en":
            mes=content["message"]
            message="HMAC_en_result"
            package=HMAC_en(mes)     
        elif dict["type"]=="HMAC_de":
            mes=content["message"]
            message="HMAC_de_result"
            key=content["key"]
            tag=content["tag"]
            package=HMAC_de(mes, key, tag)
            
            
        elif dict["type"]=="poly1305_en":
            mes=content["message"]
            message="poly1305_en_result"
            package=poly1305_en(mes) 
        elif dict["type"]=="poly1305_de":
            mes=content["message"]
            message="poly1305_de_result"
            key=content["key"]
            tag=content["tag"]
            package=poly1305_de(mes, key, tag)   
                
            
        elif dict["type"]=="SHA_family_de":
            mes=content["message"]
            message="SHA_family_result"
            type_sha=content["type_sha"]
            package=SHA_family(mes, type_sha)  
        elif dict["type"]=="Shake_family":
            mes=content["message"]
            message="Shake_family_result"
            len_output=content["len_output"]
            type_shake=content["type_shake"] 
            package=Shake_family(mes, len_output, type_shake)    
        
        
        elif dict["type"]=="embed_text":
            image_path=content["image_path"]
            message="embed_text_result"
            text=content["text"]
            output_path=content["output_path"] 
            package=embed_text(image_path, text, output_path)
        elif dict["type"]=="get_text":
            image_path=content["image_path"]
            message="get_text_result"
            len_wm=content["len_wm"]
            output_path=content["output_path"] 
            package=get_text(image_path,len_wm,output_path)
        elif dict["type"]=="embed_img":
            image_path=content["image_path"]
            message="embed_img_result"
            wm_path=content["wm_path"]
            output_path=content["output_path"] 
            package=embed_img(image_path, wm_path,output_path)
        elif dict["type"]=="get_img":
            image_path=content["image_path"]
            message="get_img_result"
            width=content["width"]
            height=content["height"]
            output_path=content["output_path"] 
            package=get_img(image_path, output_path, width, height)
        
        
    elif dict["source"]=="snmp":
        if dict["type"]=="start":
            print("snmp_start")
            snmping[0]=True
            message="snmp_start"
        elif dict["type"]=="get":
            print("snmp_get")
            des=dict["content"]["des"]
            oid=dict["content"]["oid"]
            package=GetByOid(des, oid)
            message="snmp_get"
        elif dict["type"]=="stop":
            message="snmp_start"
            snmping[0]=False
            print(message)
    elif dict["source"]=="state_monitor":
        if dict["type"]=="start":
            des_ip[0]=dict["des_ip"]
            state_monitoring[0]=True
            message="monitor_start"
        elif dict["type"]=="stop":
            state_monitoring[0]=False
            print("monitor_stop")
            message="monitor_stop"
    
    return {
        "message_type":"server_reply",
        "message":message,
        "package":package
    }

    
    
    
    
    
    
    
    
    
    
    
# ----------------------------------------------------------------

# MAIN PART

# ----------------------------------------------------------------
# 创建sniffer线程

if SNIFFER_AVAILABLE:
	threading.Thread(target=sniff_packets).start()  
if SNMP_AVAILABLE:
	trapListener=TrapListener()
	threading.Thread(target=trapListener.listenTrap).start() 
if STATE_MONITOR_AVAILABLE:
	threading.Thread(target=start_monitor_state).start() 
 

server = websockets.serve(echo, "0.0.0.0", 8765)
asyncio.get_event_loop().run_until_complete(server)
asyncio.get_event_loop().run_forever()

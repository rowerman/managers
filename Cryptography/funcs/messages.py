AES = "AES密码与分组密码Rijndael基本上完全一致，Rijndael分组大小和密钥大小都可以为128位、192位和256位。然而AES只要求分组大小为128位，因此只有分组长度为128Bit的Rijndael才称为AES算法。本文只对分组大小128位，密钥长度也为128位的Rijndael算法进行分析。密钥长度为192位和256位的处理方式和128位的处理方式类似，只不过密钥长度每增加64位，算法的循环次数就增加2轮，128位循环10轮、192位循环12轮、256位循环14轮。"

Camellia = "Camellia算法由NTT和Mitsubishi Electric Corporation联合开发。作为欧洲新一代的加密标准,它具有较强的安全性,能够抵抗差分和线性密码分析等已知的攻击。与AES算法相比,Camellia算法在各种软硬件平台上表现出与之相当的加密速度。除了在各种软件和硬件平台上的高效性这一显著特点,它的另外一个特点是针对小规模硬件平台的设计。整个算法的硬件执行过程包括加密、解密和密钥扩展三部分,只需占用8.12K 0.18μm COMS工艺ASIC的库门逻辑。这在现有128比特分组密码中是最小的。"

ChaChaPoly1305 = "ChaCha20-Poly1305是Google所采用的一种新式加密算法，性能强大，在CPU为精简指令集的ARM平台上尤为显著（ARM v8前效果较明显），在同等配置的手机中表现是AES的4倍（ARM v8之后加入了AES指令，所以在这些平台上的设备，AES方式反而比chacha20-Poly1305方式更快，性能更好），可减少加密解密所产生的数据量进而可以改善用户体验，减少等待时间，节省电池寿命等。谷歌选择了ChaCha20和伯恩斯坦的Poly1305消息认证码取代过去一直在互联网安全领域使用的基于OpenSSL的RC4密码，谷歌最初是为了保证能够在Android手机上的Chrome浏览器和谷歌网站间的HTTPS（TLS/SSL）通讯"

SM4 = "SM4.0（原名SMS4.0）是中华人民共和国政府采用的一种分组密码标准，由国家密码管理局于2012年3月21日发布。相关标准为“GM/T 0002-2012《SM4分组密码算法》（原SMS4分组密码算法）”。在商用密码体系中，SM4主要用于数据加密，其算法公开，分组长度与密钥长度均为128bit，加密算法与密钥扩展算法都采用32轮非线性迭代结构，S盒为固定的8比特输入8比特输出。SM4.0中的指令长度被提升到大于64K（即64×1024）的水平，这是SM 3.0规格（渲染指令长度允许大于512）的128倍。"

RSA = "SA公钥加密算法是1977年由罗纳德·李维斯特（Ron Rivest）、阿迪·萨莫尔（Adi Shamir）和伦纳德·阿德曼（Leonard Adleman）一起提出的。1987年首次公布，当时他们三人都在麻省理工学院工作。RSA就是他们三人姓氏开头字母拼在一起组成的。RSA是目前最有影响力的公钥加密算法，它能够抵抗到目前为止已知的绝大多数密码攻击，已被ISO推荐为公钥数据加密标准。今天只有短的RSA钥匙才可能被强力方式解破。到2008年为止，世界上还没有任何可靠的攻击RSA算法的方式。只要其钥匙的长度足够长，用RSA加密的信息实际上是不能被解破的。但在分布式计算和量子计算机理论日趋成熟的今天，RSA加密安全性受到了挑战。RSA算法基于一个十分简单的数论事实：将两个大质数相乘十分容易，但是想要对其乘积进行因式分解却极其困难，因此可以将乘积公开作为加密密钥。RSA算法是现今使用最广泛的公钥密码算法，也是号称地球上最安全的加密算法。在了解RSA算法之前，先熟悉下几个术语根据密钥的使用方法，可以将密码分为对称密码和公钥密码"

Ed25519 = "Curve25519/Ed25519/X25519 是著名密码学家 Daniel J. Bernstein 在 2006 年独立设计的椭圆曲线加密 /签名 /密钥交换算法，和现有的任何椭圆曲线算法都完全独立，其中Ed25519用于签名，可在区块链中进行签名，Stellar就是使用了Ed25519作为签名算法的"

Ed448_key = "略"

Ed448_sig = "略"

CMAC = "CMAC（Cipher Block Chaining-Message Authentication Code），也简称为CBC_MAC，它是一种基于对称秘钥分组加密算法的消息认证码。由于其是基于“对称秘钥分组算法”的，故可以将其当做是对称算法的一种操作模式。  CMAC可以应用的算法主要有：AES、DES、3DES等"

HMAC = "MAC（Hash-based Message Authentication Code，散列消息认证码）是一种使用密码散列函数，同时结合一个加密密钥，通过特别计算方式之后产生的消息认证码（MAC）。它可以用来保证数据的完整性，同时可以用来作某个消息的身份验证。HMAC算法 是一种基于密钥的报文完整性的验证方法。HMAC算法利用哈希运算，以一个密钥和一个消息为输入，生成一个消息摘要作为输出。其安全性是建立在Hash加密算法基础上的。它要求通信双方共享密钥、约定算法、对报文进行Hash运算，形成固定长度的认证码。通信双方通过认证码的校验来确定报文的合法性。HMAC算法可以用来作加密、数字签名、报文验证等"

poly1305 = "略"

SHA2_SHA3 = "略"

Shake = "略"

embed_text = "https://github.com/guofei9987/blind_watermark/blob/master/blind_watermark/blind_watermark.py"

embed_img = "https://github.com/guofei9987/blind_watermark/blob/master/blind_watermark/blind_watermark.py"

intro = {
	"AES": AES,
	"Camellia": Camellia,
	"ChaChaPoly1305": ChaChaPoly1305,
	"SM4": SM4,
	"RSA": RSA,
	"Ed25519": Ed25519,
	"Ed448_key": Ed448_key,
	"Ed448_sig": Ed448_sig,
	"CMAC": CMAC,
	"HMAC": HMAC,
	"poly1305": poly1305,
	"SHA2/SHA3": SHA2_SHA3,
	"Shake": Shake,
	"embed_text": embed_text,
	"embed_img": embed_img,
}


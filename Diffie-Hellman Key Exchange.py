# Understanding Diffie-Hellman Key Exchange

def pickSecretKey(p):
    a = getRandomRange(3,p-2)
    while GCD(a,p-1) != 1:
        a = getRandomRange(3,p-2)
    return a

def generateAlicekeys():
    p=getStrongPrime(1024)
    g=3
    a=pickSecretKey(p)
    publicKey = pow(g,a,p)
    print("PART 1 OF SETTING UP: person A to person B")
    print("SHARE THESE 3 VALUES IN THE CHAT")
    print("p={}".format(p))
    print("g={}".format(g))
    print("A={}".format(publicKey))

    print("copy paste this SECRET VALUE for a future stage")
    print("a={}".format(a))

def generateBobkeys(p,g,A):
    
    b=pickSecretKey(p)
    publicKey = pow(g,A,p)

    secretSharedKey = pow(A,b,p)
    print("PART 2: person B to person A")
    print("SHARE THIS 1 VALUE")
    print("B={}".format(publicKey))

    print("copy paste this SHARED VALUE")
    print("b={}".format(secretSharedKey))

    print("Now you're ready to send encryption stuff")

def calculatealicesecretkey(p,g,a,B):

   secretSharedKey = pow(B,a,p)
   print("copy paste this SHARED VALUE")
   print("b={}".format(secretSharedKey))

   print("Now you're ready to send encryption stuff")

def encrypt(yourmessage,secretSharedKey):
    skh=hashlib.sha256(long_to_bytes(secretSharedKey)).digest()
    IV=os.urandom(16)

    cipher = AES.new(skh, IV=IV, mode=AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(yourmessage,16))
    print("cipertext =bytes.fromhex(\"{}\")".format(ciphertext.hex()))
    print("IV =bytes.fromhex(\"{}\")".format(IV.hex()))

def decrypt(ciphertext_hex,IV_hex,secretSharedKey):

   ciphertext=bytes.fromhex(ciphertext_hex)
   IV=bytes.fromhex(IV_hex)
   skh=hashlib.sha256(long_to_bytes(secretSharedKey)).digest()
   cipher = AES.new(skh, IV=IV, mode=AES.MODE_CBC)
   plaintext = unpad(cipher.decrypt(ciphertext),16)
   print("plaintext ={}".format(plaintext))


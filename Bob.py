# PROGRAM B
import os
import tinyec.ec as ec
import tinyec.registry as reg
import random
import hashlib
mycurve = reg.get_curve("secp256r1")

# Samples two group elements from curve P-256
s = random.SystemRandom().randrange(1,mycurve.field.n)
s2 = random.SystemRandom().randrange(1,mycurve.field.n)
group_element = s*mycurve.g
group_element2 = s2*mycurve.g

# Receives two group elements from Alice
input("Press Enter to receive two group elements from Alice")
f = open("message.txt","r")
array_msg = f.readlines()
f.close()
os.remove("message.txt")
other_group_element = ec.Point(mycurve, int(array_msg[0]), int(array_msg[1]))
other_group_element1 = ec.Point(mycurve, int(array_msg[2]), int(array_msg[3]))
print("I received from Alice:")
print(other_group_element)
print(other_group_element1)

# Sends your two group elements to Alice
input("Press Enter to send two groups elements to Alice")
print("I am sending you my 2 group elements")
f = open("message.txt","w")
f.write(str(group_element.x))
f.write("\n")
f.write(str(group_element.y))
f.write("\n")
f.write(str(group_element2.x))
f.write("\n")
f.write(str(group_element2.y))
f.close()
print("I sent you Alice:")
print(group_element)
print(group_element2)

# Set hashed first key to be alpha
alpha = s
alpha_gelement = alpha*other_group_element
alphahash = hashlib.sha256()
alphahash.update(alpha_gelement.x.to_bytes(32,"big"))
alphahash.update(alpha_gelement.y.to_bytes(32,"big"))
alpha = int("0x"+alphahash.hexdigest(),16)
print("First key: " + str(alpha))

# Set hashed second key to be beta
beta = s2
beta_gelement = beta*other_group_element1
betahash = hashlib.sha256()
betahash.update(beta_gelement.x.to_bytes(32,"big"))
betahash.update(beta_gelement.y.to_bytes(32,"big"))
beta = int("0x"+betahash.hexdigest(),16)
print("Second key: " + str(beta))

# PRG function to generate a key based on given message
def PRG(bin_enc,alpha,beta):
    buildbit = ""
    appendcount = int((len(bin_enc)/256) + ((len(bin_enc)%256) > 0))
    for i in range(appendcount):
        alpha_gelement = alpha*mycurve.g
        beta_gelement = beta*mycurve.g
        gamma = alpha*beta
        gamma_gelement = gamma*mycurve.g
        alphahash = hashlib.sha256()
        alphahash.update(alpha_gelement.x.to_bytes(32,"big"))
        alphahash.update(alpha_gelement.y.to_bytes(32,"big"))
        alpha = int("0x"+alphahash.hexdigest(),16)
        betahash = hashlib.sha256()
        betahash.update(beta_gelement.x.to_bytes(32,"big"))
        betahash.update(beta_gelement.y.to_bytes(32,"big"))
        beta = int("0x"+betahash.hexdigest(),16)
        gammahash = hashlib.sha256()
        gammahash.update(gamma_gelement.x.to_bytes(32,"big"))
        gammahash.update(gamma_gelement.y.to_bytes(32,"big"))
        gammaint = int("0x"+gammahash.hexdigest(),16)
        buildbit = buildbit + str(bin(gammaint)[2:])
    if len(str(buildbit)) < (appendcount*256):
        remainder = (appendcount*256) - len(str(buildbit))
        alpha_gelement = alpha*mycurve.g
        beta_gelement = beta*mycurve.g
        gamma = alpha*beta
        gamma_gelement = gamma*mycurve.g
        alphahash = hashlib.sha256()
        alphahash.update(alpha_gelement.x.to_bytes(32,"big"))
        alphahash.update(alpha_gelement.y.to_bytes(32,"big"))
        alpha = int("0x"+alphahash.hexdigest(),16)
        betahash = hashlib.sha256()
        betahash.update(beta_gelement.x.to_bytes(32,"big"))
        betahash.update(beta_gelement.y.to_bytes(32,"big"))
        beta = int("0x"+betahash.hexdigest(),16)
        gammahash = hashlib.sha256()
        gammahash.update(gamma_gelement.x.to_bytes(32,"big"))
        gammahash.update(gamma_gelement.y.to_bytes(32,"big"))
        gammaint = int("0x"+gammahash.hexdigest(),16)
        buildbit = buildbit + str(bin(gammaint)[2:remainder+2])
    return([buildbit,alpha,beta])

ProtocolsCount = 4 # Number of paired messages to have between Alice and Bob.  Example: 2 protocols result in a total of 2 messages from Alice and 2 messages from Bob.
cTrack = 0
while cTrack < ProtocolsCount:
    cTrack = cTrack + 1
    print("Start of Protocol " + str(cTrack))
    print("\n")
    # Receive encrypted message from Alice
    input("Press Enter to receive a message from Alice")
    f = open("message.txt", "r")
    ciphertext=f.read()
    f.close()
    os.remove("message.txt")
    print("Encrypted message received from Alice: " + str(ciphertext))

    # Generates appropriate key for message
    key,alpha,beta = PRG(ciphertext,alpha,beta)
    print("Generated key for decrypting: " + str(key))

    # Decrypt the message from Alice
    dec = ""
    for i in range(len(ciphertext)):
        dec = dec + bin(int(key[i])^int(ciphertext[i]))[2]
    conv = ""
    for i in range(int(len(dec)/8)):
        i = i + 1
        conv = conv + chr(int(dec[((i-1)*8):(i*8)],2))
    print("Alice's decrypted message: " + str(conv))

    # Constructing a message for Alice
    input("Press Enter to send a message to Alice")
    m = input("Enter your message: ")
    bin_enc = ""
    for i in m:
        bin_enc = bin_enc + bin(ord(i))[2:].zfill(8)
    print("Binary form of message = " + str(bin_enc))

    # Generates appropriate key for message
    key,alpha,beta = PRG(bin_enc,alpha,beta)
    print("Generated key for encrypting: " + str(key))

    # Encrypts message with generated key
    ciphertext = ""
    for i in range(len(bin_enc)):
        ciphertext = ciphertext + bin(int(key[i])^int(bin_enc[i]))[2]

    # Send encrypted message to Alice
    f = open("message.txt", "w")
    f.write(ciphertext)
    f.close()
    print("Encrypted message sent to Alice: " + str(ciphertext))
    print("End of Protocol " + str(cTrack))
    print("\n")
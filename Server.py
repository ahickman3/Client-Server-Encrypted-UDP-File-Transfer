#socket_echo_server.py
import socket
from Crypto.Cipher import AES
import time
import os.path

# closing will close the file and exit the client program
def closing():
    print('closing socket')
    s.close()
    exit()

#sending will send a file to the client
def sending(fname):
    server_address = (socket.gethostname(), 10100) #create a new socket address

    #if the file doesnt exit, close the socket and exit program
    if not (os.path.exists(fname.decode('utf-8'))):
        print("file not found, closing")
        s.close()
        exit()

    f = open(fname.decode('utf-8'), 'rb') #open the requested file
    buffer = 4000  # Buffer size
    key = b'Sixteen byte key' # key = get_random_bytes(16)

    while (True):
        l = f.read(buffer) #read buffer-sized byte section of the file
        if len(l) < 1: closing() #if there is no more of the file to be read, close it and end program

        cipher = AES.new(key, AES.MODE_EAX) #create cipher object for encryption
        nonce = cipher.nonce #generate nonce number
        ciphertext, tag = cipher.encrypt_and_digest(l) #encrypt f and generate a tag for integrity-checking
        print ("sending {}".format(ciphertext))
        # concatinate the ciphertext, tag, and nonce separate by uniqueword pattern so that they can be separated on the server
        ciphertext = ciphertext + b'uniqueword' + tag + b'uniqueword' + nonce
        time.sleep(.01) #required to send each section error-free
        s.sendto(ciphertext, server_address) #send the ciphertext, tag, and nonce to the server

#receiving will recieve a file from the client
def receiving(ciphertext):
    f = open('newpdf.pdf', 'wb') #open file that will be written to
    try:
        while (True):
            ciphertext, ignore, nonce = ciphertext.rpartition(b'uniqueword') #separate nonce from ciphertext variable
            ciphertext, ignore, tag = ciphertext.rpartition(b'uniqueword')   #separate ciphertext and tag from ciphertext variable

            print('received {}'.format(ciphertext))
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce) #create cipher object for decryption
            plaintext = cipher.decrypt(ciphertext)           #decrypt cipher text


            # try to verify message with tag. If its been changed in transit, throw ValueError and close file/socket and exit
            try:
                cipher.verify(tag) #verify the tag to check integrity
                print("The message is authentic:")
            except ValueError:
                print("Key incorrect or message corrupted")
                print('closing')
                f.close()
                s.close()
                exit()
            f.write(plaintext)

            s.settimeout(2)
            ciphertext, address = s.recvfrom(buf)

    except socket.timeout:
        print('closing')
        f.close()
        s.close()
        exit()




# Create a UDP/IP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Bind the socket to the port
server_address = (socket.gethostname(), 10000)

print('starting up on {} port {}'.format(*server_address))

s.bind(server_address) #bind the socket to the address
buf = 4096 #reading buffer size
key = b'Sixteen byte key' # Generate key for AES encryption


print('waiting for a connection')
ciphertext, address = s.recvfrom(buf) #recieve ciphertext sent

#if there is an isafile in a message, call sending function, else call receiving function
ignore1, ignore2, filename = ciphertext.rpartition(b'isafile')
if ignore2:
    sending(filename)
else:
    receiving(ciphertext)






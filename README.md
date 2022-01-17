# secure-sockets
8 October 2021<br />
author: Ariel Gluzman (ariel.gluzman@gmail.com)<br /><br />
## secureServer
About _**secureServer**_:<br />&nbsp;&nbsp;&nbsp;
class secureServer implements RSA encryption method using [Pycrypto](https://pycryptodome.readthedocs.io/en/latest/), [rsa](https://stuvel.eu/python-rsa-doc/) and [pickle](https://docs.python.org/3/library/pickle.html#module-pickle) tools.<br />&nbsp;&nbsp;&nbsp;
_secureServer_ follows the usage of network sockets of the higher layer-hierarchy, identically,<br />&nbsp;&nbsp;&nbsp;&nbsp;
the return values, and functionality its values remind of those of the default 'socket' library.<br />&nbsp;&nbsp;&nbsp;&nbsp;
->	i.e. to _bind()_ the socket, _listen()_, and _accept()_ a client connection.<br />&nbsp;&nbsp;&nbsp;&nbsp;
with that being said the major difference apart from the encryption, that is mentioned previously,<br />&nbsp;&nbsp;&nbsp;&nbsp;
is that server and client have two different classes, which are one at default 'socket' library,<br />&nbsp;&nbsp;&nbsp;&nbsp;
therefore an important thing to notice while using secureServer is that the return-type that is<br />&nbsp;&nbsp;&nbsp;&nbsp;
returned with _secureServer.accept()_ is a _secureClient()_.<br />&nbsp;&nbsp;&nbsp;&nbsp;
_secureServer()_ is merely a tool for connecting to clients with an addition of the RSA protocol,<br />&nbsp;&nbsp;&nbsp;&nbsp;
after recieving an encryption key from client, it immediately returns a _secureClient()_,<br />&nbsp;&nbsp;&nbsp;&nbsp;
and waits for as many clients defined to be able to at _secureServer.listen()_<br />&nbsp;&nbsp;&nbsp;&nbsp;
****Warning**: secure_sockets(secureServer/secureClient) use [Block Cipher Mode ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)), which deficiency is encryption<br />&nbsp;&nbsp;&nbsp;&nbsp;
of pictures which can still be understood post encryption, therefore 'secure_sockets' should not be<br />&nbsp;&nbsp;&nbsp;&nbsp;
used for encryption of photos.
* **bind()** - exactly _socket.socket.bind()_
* **listen()** - exactly _socket.socket.listen()_
* **accept()** - uses _socket.socket.accept()_ and receives symmetric key of *default* length 32 bytes, returns _secureClient_

## secureClient
About _**secureClient**_:<br />&nbsp;&nbsp;&nbsp;&nbsp;
an encapsulation of [RSA key transfer](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Key_distribution), [AES encryption](https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html) and socket connection and function.<br />&nbsp;&nbsp;&nbsp;&nbsp;
by using _connect()_, _send()_ and _receive()_ the user is implementing all three components.
* **connect()** - uses _socket.socket.connect()_ generates symmetric-key of *default* length 32 bytes, receives [public-key](https://stuvel.eu/python-rsa-doc/reference.html#rsa.PublicKey) from server, encryptes symmetric-key with public-key and sends ciphertext i.e. the encrypted symmetric-key
* **send(bytes)** - bytes: plaintext, Encrypts _plaintext_ with symmetric-key and sends using _socket.socket.send()_.
* **recv()** - receives using _socket.socket.recv(bytes)_ and decrypts using symmetric-key.

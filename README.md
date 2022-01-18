17 January 2022<br />
author: Ariel Gluzman (ariel.gluzman@gmail.com)<br /><br />

# secure-sockets
A close copy of a few very frequently used functions of ***socket.socket()***[^1], that integrates high standard encryption protocols
that remain far from the eye.

## encryption

***SecureSocket*** integrates two concepts of [cryptography](https://www.kaspersky.com/resource-center/definitions/what-is-cryptography),
Public-key cryptography and symmetric cryptography, </br>
those take form in RSA and AES protocols.
### RSA
[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) protocol was implemented using [rsa](https://stuvel.eu/python-rsa-doc/) library,
public key transfer used [pickle](https://docs.python.org/3/library/pickle.html#module-pickle) library to serialize a [_rsa.PublicKey_](https://stuvel.eu/python-rsa-doc/reference.html#rsa.PublicKey) object and distribute it.
### AES
[AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) protocol was implemented using [PycryptoDome](https://pycryptodome.readthedocs.io/en/latest/index.html) library


****Warning**: '_SecureSocket_' uses [Block Cipher Mode ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)), which deficiency is encryption of pictures which remain somewhat visible post encryption[^2].

## public methods
* bind([address ,port]) - Bind socket to to inteface at _address_ on port number _port_, executes [_socket.socket.bind()_ ](https://docs.python.org/3/library/socket.html#socket.socket.bind).
* listen(backlog) - Enable a server to accept connections, executes [_socket.socket.listen()_](https://docs.python.org/3/library/socket.html#socket.socket.listen).
* accept() - Accept a connection. returns a pair `(s,a)` where `s` is a connected SecureSocket and `a` is a tuple of address and port. executes [_socket.socket.accept()_](https://docs.python.org/3/library/socket.html#socket.socket.accept).
* connect([address ,port]) - Connect to a remote socket at address 'address', port 'port', and set symmetric key. executes[_socket.socket.connect()_](https://docs.python.org/3/library/socket.html#socket.socket.connect).
* send(plaintext) - Encrypt _plaintext_ and sends to socket at other end, executes [_socket.socket.send()_](https://docs.python.org/3/library/socket.html#socket.socket.send).
* recv() - Receives and decrypts and pending message, knows exact size using message formating [_socket.socket.recv()_](https://docs.python.org/3/library/socket.html#socket.socket.recv).
* close() - Release related resources, executes [_socket.socket.close()_](https://docs.python.org/3/library/socket.html#socket.socket.close).

[^1]: see [Python Socket](https://docs.python.org/3/library/socket.html)
[^2]: image [before](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#/media/File:Tux.jpg) and [after](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#/media/File:Tux_ecb.jpg) after encrypted in ECB Mode

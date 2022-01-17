17 January 2022<br />
author: Ariel Gluzman (ariel.gluzman@gmail.com)<br /><br />

# secure-sockets
A close copy of a few very frequently used functions of ***socket.socket()***[^1], that integrates high standard encryption protocols
that remain far from the eye.

## encryption

***SecureSocket*** integrates concepts of [cryptography](https://www.kaspersky.com/resource-center/definitions/what-is-cryptography),
Public-key cryptography and symmetric cryptography, </br>
those take form in RSA and AES.
### RSA
[RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) protocol was implemented using [rsa](https://stuvel.eu/python-rsa-doc/) library,
public key transfer used [pickle](https://docs.python.org/3/library/pickle.html#module-pickle) library to serialize a [_rsa.PublicKey_](https://stuvel.eu/python-rsa-doc/reference.html#rsa.PublicKey) object and distribute it.
### AES
[AES]() protocol was implemented using [PycryptoDome]() library


****Warning**: '_SecureSocket_' uses [Block Cipher Mode ECB](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)), which deficiency is encryption of pictures which remain somewhat visible post encryption[^2].

## public methods
* bind()
* listen()
* accept()
* connect()
* send()
* recv()

[^1]: see [Python Socket](https://docs.python.org/3/library/socket.html)
[^2]: image [before](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#/media/File:Tux.jpg) and [after](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#/media/File:Tux_ecb.jpg) after encrypted in ECB Mode

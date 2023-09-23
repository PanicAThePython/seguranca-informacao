# Natália Sens Weise e Matheus Petters Bevilaqua
from Crypto.Cipher import Blowfish
from struct import pack
from Crypto import Random

bs = Blowfish.block_size
key = b'ABCDE'
cipherECB = Blowfish.new(key, Blowfish.MODE_ECB)

plaintext = b'FURB'
plen = bs - len(plaintext) % bs
padding = [plen]*plen
padding = pack('b'*plen, *padding)
msg = cipherECB.encrypt(plaintext + padding)
print('1.1 '+ str(msg.hex()))
print('1.2 '+ str(len(msg)))

plaintext = b'COMPUTADOR'
plen = bs - len(plaintext) % bs
padding = [plen]*plen
padding = pack('b'*plen, *padding)
msg = cipherECB.encrypt(plaintext + padding)
print('2.1 '+ str(msg.hex()))
print('2.2 '+ str(len(msg)))
print('2.3 Possui tamanho 16 pois precisou de 2 blocos, visto que computador tem 10 caracteres e cada bloco são 8 bytes')

plaintext = b'SABONETE'
plen = bs - len(plaintext) % bs
padding = [plen]*plen
padding = pack('b'*plen, *padding)
msg = cipherECB.encrypt(plaintext + padding)
print('3.1 '+ str(msg.hex()))
print('3.2 '+ str(len(msg)))
print('3.3 Porque o final da mensagem sempre deve ser preenchido com o padding, necessitando de mais um bloco de 8 bytes')

plaintext = b'SABONETESABONETESABONETE'
plen = bs - len(plaintext) % bs
padding = [plen]*plen
padding = pack('b'*plen, *padding)
msg = cipherECB.encrypt(plaintext + padding)
print('4.1 '+ str(msg.hex()))
print('4.2 '+ str(len(msg)))
print('4.3 Assim como no texto simples, o conteúdo se repete no texto cifrado')

iv = Random.new().read(bs)
cipherCBC = Blowfish.new(key, Blowfish.MODE_CBC, iv)
plaintext = b'FURB'
plen = bs - divmod(len(plaintext),bs)[1]
padding = [plen]*plen
padding = pack('b'*plen, *padding)
msg = iv+cipherCBC.encrypt(plaintext + padding)
print('5.1 '+ str(msg.hex()))
# print('5.2 '+ cipherCBC.decrypt(msg)) essa aqui n sei oq responder
print('5.2 Dá erro, pois não conheço o vetor de inicialização')

plaintext = b'FURB'
plen = bs - divmod(len(plaintext),bs)[1]
padding = [plen]*plen
padding = pack('b'*plen, *padding)
msg = iv + cipherCBC.encrypt(plaintext + padding)
print('6.1 '+ str(msg))
print('6.1 em hex: '+ str(msg.hex()))

#ex07
iv = bytes([1,1,2,2,3,3,4,4])
cipherCBC = Blowfish.new(key, Blowfish.MODE_CBC, iv)
plaintext = b'SABONETESABONETESABONETE'
plen = bs - divmod(len(plaintext),bs)[1]
padding = [plen]*plen
padding = pack('b'*plen, *padding)
msg = iv + cipherCBC.encrypt(plaintext + padding)
print('7.1 '+ str(msg.hex()))
print('7.2 A resposta da 7 apresenta dois blocos de encriptação a mais que a 4')

iv = bytes([10,20,30,40,50,60,70,80])
cipherCBC = Blowfish.new(key, Blowfish.MODE_CBC, iv)
plaintext = b'SABONETESABONETESABONETE'
plen = bs - divmod(len(plaintext),bs)[1]
padding = [plen]*plen
padding = pack('b'*plen, *padding)
msg = iv + cipherCBC.encrypt(plaintext + padding)
ivnew = bytes([1,1,2,2,3,3,4,4])
cipherCBC2 = Blowfish.new(key, Blowfish.MODE_CBC, ivnew)
print('8.1 '+ str(msg.hex()))
print('8.2 A partir da mudança do vetor de inicialização nota-se que a saida é diferente, dado que o bloco utilizado na primeira cifragem é diferente, alterando toda a cifra')
print('8.3 Mensagem descriptografada: '+ str(cipherCBC2.decrypt(msg).hex())+'. Atingimos um valor diferente do esperado dada a mudança no vetor de inicialização, que altera toda a cifra')

plaintext = b'FURB'
plen = bs - len(plaintext) % bs
padding = [plen]*plen
padding = pack('b'*plen, *padding)
msg = cipherECB.encrypt(plaintext + padding)
cipher = Blowfish.new(b'11111', Blowfish.MODE_ECB)
rsp = cipher.decrypt(msg)
print('9.1 Como não foi usada a mesma chave para decifrar, não foi possível descobrir a mensagem original, ficando da seguinte forma: '+str(rsp))

import os
cipher = Blowfish.new(key, Blowfish.MODE_ECB)
infilepath = './L07 - Criptografia Blowfish.pdf'
infile = open(infilepath, 'rb')
outfile = open('./saida.bin', 'wb')
data = infile.read()
infile.close()
plen = bs - len(data) % bs
padding = [plen]*plen
padding = pack('b'*plen, *padding)
msg = cipherECB.encrypt(data + padding)
outfile.write(msg)
outfile.close()
size = os.path.getsize('./saida.bin')
print('10.1 '+ str(size))

infile = open('./saida.bin', 'rb')
outfile = open('./descriptografado.pdf', 'wb')
data = infile.read()
infile.close()

rsp = cipherECB.decrypt(data)
print('11.1 o pdf abre mostrando o conteúdo original')

outfile.write(rsp)
outfile.close()

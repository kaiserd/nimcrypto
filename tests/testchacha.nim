## tests input from rfc8439
## further tests are marked with (non RFC)

import system, os

import nimcrypto/utils
import ../nimcrypto/chacha
import unittest

suite "Chacha20 Tests":

  test "Chacha20 basic operations":
      var a = 0x11111111'u32
      var b = 0x01020304'u32
      var c = 0x77777777'u32
      var d = 0x01234567'u32
      c = c + d
      b = b xor c
      check:
        c == 0x789abcde'u32
        b == 0x7998bfda'u32
      b = ROL(b,7)
      check:
        b == 0xcc5fed3c'u32

  test "Chacha20 quater round standallone":
    var a = 0x11111111'u32
    var b = 0x01020304'u32
    var c = 0x9b8d6f43'u32
    var d = 0x01234567'u32
    (a,b,c,d) = quaterRoundStandallone(a, b, c, d);
    check:
      a == 0xea2a92f4'u32
      b == 0xcb1cf8ce'u32
      c == 0x4581472e'u32
      d == 0x5881c4bb'u32

  test "Chacha20 quater round":
    var stateInput = [
      0x879531e0'u32,  0xc5ecf37d'u32,  0x516461b1'u32,  0xc9a62f8a'u32,
      0x44c20ef3'u32,  0x3390af7f'u32,  0xd9fc690b'u32,  0x2a5f714c'u32,
      0x53372767'u32,  0xb00a5631'u32,  0x974c541a'u32,  0x359e9963'u32,
      0x5c971061'u32,  0x3d631689'u32,  0x2098d9d6'u32,  0x91dbd320'u32,
    ]
    var stateExpectedResult =  [
      0x879531e0'u32,  0xc5ecf37d'u32,  0xbdb886dc'u32,  0xc9a62f8a'u32,
      0x44c20ef3'u32,  0x3390af7f'u32,  0xd9fc690b'u32,  0xcfacafd2'u32,
      0xe46bea80'u32,  0xb00a5631'u32,  0x974c541a'u32,  0x359e9963'u32,
      0x5c971061'u32,  0xccc07c79'u32,  0x2098d9d6'u32,  0x91dbd320'u32,
    ]
    var ctx = Chacha20()
    ctx.init(stateInput)
    ctx.quaterRound(2, 7, 8, 13)
    check:
      ctx.state == stateExpectedResult


  test "Chacha20 20 block rounds":
    var stateInput = [
      0x61707865'u32,  0x3320646e'u32,  0x79622d32'u32,  0x6b206574'u32,
      0x03020100'u32,  0x07060504'u32,  0x0b0a0908'u32,  0x0f0e0d0c'u32,
      0x13121110'u32,  0x17161514'u32,  0x1b1a1918'u32,  0x1f1e1d1c'u32,
      0x00000001'u32,  0x09000000'u32,  0x4a000000'u32,  0x00000000'u32,
    ]
    var stateExpectedResult = [
      0x837778ab'u32,  0xe238d763'u32,  0xa67ae21e'u32,  0x5950bb2f'u32,
      0xc4f2d0c7'u32,  0xfc62bb2f'u32,  0x8fa018fc'u32,  0x3f5ec7b7'u32,
      0x335271c2'u32,  0xf29489f3'u32,  0xeabda8fc'u32,  0x82e46ebd'u32,
      0xd19c12b4'u32,  0xb04e16de'u32,  0x9e83d0cb'u32,  0x4e3c50a2'u32,
    ]
    var ctx = Chacha20()
    ctx.init(stateInput)
    ctx.chacha20BlockRounds()
    check:
      ctx.state == stateExpectedResult

  test "Chacha20 block (20 rounds & add original state)":
    var stateInput = [
      0x61707865'u32,  0x3320646e'u32,  0x79622d32'u32,  0x6b206574'u32,
      0x03020100'u32,  0x07060504'u32,  0x0b0a0908'u32,  0x0f0e0d0c'u32,
      0x13121110'u32,  0x17161514'u32,  0x1b1a1918'u32,  0x1f1e1d1c'u32,
      0x00000001'u32,  0x09000000'u32,  0x4a000000'u32,  0x00000000'u32,
    ]
    var stateExpectedResult = [
      0xe4e7f110'u32,  0x15593bd1'u32,  0x1fdd0f50'u32,  0xc47120a3'u32,
      0xc7f4d1c7'u32,  0x0368c033'u32,  0x9aaa2204'u32,  0x4e6cd4c3'u32,
      0x466482d2'u32,  0x09aa9f07'u32,  0x05d7c214'u32,  0xa2028bd9'u32,
      0xd19c12b5'u32,  0xb94e16de'u32,  0xe883d0cb'u32,  0x4e3c50a2'u32,
    ]
    var ctx = Chacha20()
    ctx.init(stateInput)
    ctx.chacha20Block()
    check:
      ctx.state == stateExpectedResult

  test "Chacha20 reset and increment counter": # non RFC
    var stateInput = [
      0x61707865'u32,  0x3320646e'u32,  0x79622d32'u32,  0x6b206574'u32,
      0x03020100'u32,  0x07060504'u32,  0x0b0a0908'u32,  0x0f0e0d0c'u32,
      0x13121110'u32,  0x17161514'u32,  0x1b1a1918'u32,  0x1f1e1d1c'u32,
      0x00000001'u32,  0x09000000'u32,  0x4a000000'u32,  0x00000000'u32,
    ]
    var stateExpectedResult = [
      0x61707865'u32,  0x3320646e'u32,  0x79622d32'u32,  0x6b206574'u32,
      0x03020100'u32,  0x07060504'u32,  0x0b0a0908'u32,  0x0f0e0d0c'u32,
      0x13121110'u32,  0x17161514'u32,  0x1b1a1918'u32,  0x1f1e1d1c'u32,
      0x00000002'u32,  0x09000000'u32,  0x4a000000'u32,  0x00000000'u32,
    ]
    var ctx = Chacha20()
    ctx.init(stateInput)
    ctx.chacha20Block() # do 20 chacha rounds to mix the state
    ctx.addOriginalState()
    ctx.resetState()
    ctx.incrementCounter()
    check:
      ctx.originalState == stateExpectedResult
      ctx.state         == stateExpectedResult

  test "Chacha20 setup state":
    var stateInput = [
      0x61707865'u32,  0x3320646e'u32,  0x79622d32'u32,  0x6b206574'u32,
      0x03020100'u32,  0x07060504'u32,  0x0b0a0908'u32,  0x0f0e0d0c'u32,
      0x13121110'u32,  0x17161514'u32,  0x1b1a1918'u32,  0x1f1e1d1c'u32,
      0x00000001'u32,  0x09000000'u32,  0x4a000000'u32,  0x00000000'u32,
    ]
    let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let nonce = fromHex("000000090000004a00000000")
    let counter = 1'u32
    var ctx = Chacha20()
    ctx.init(key, nonce, counter)
    check:
      ctx.originalState == stateInput
      ctx.state          == stateInput

  test "Chacha20 setup state & generate keyStreamBlock":
    var stateExpectedResult = [
      0xe4e7f110'u32,  0x15593bd1'u32,  0x1fdd0f50'u32,  0xc47120a3'u32,
      0xc7f4d1c7'u32,  0x0368c033'u32,  0x9aaa2204'u32,  0x4e6cd4c3'u32,
      0x466482d2'u32,  0x09aa9f07'u32,  0x05d7c214'u32,  0xa2028bd9'u32,
      0xd19c12b5'u32,  0xb94e16de'u32,  0xe883d0cb'u32,  0x4e3c50a2'u32,
    ]
    let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let nonce = fromHex("000000090000004a00000000")
    let counter = 1'u32
    var ctx = Chacha20()
    ctx.init(key, nonce, counter)
    ctx.chacha20Block()
    check:
      ctx.state == stateExpectedResult

  test "Chacha20 extractKeyStreamBlock & serialized keyStreamBlock":
    var expectedHexOutput = "10F1E7E4D13B5915500FDD1FA32071C4C7D1F4C733C068030422AA9AC3D46C4ED2826446079FAA0914C2D705D98B02A2B5129CD1DE164EB9CBD083E8A2503C4E"
    let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let nonce = fromHex("000000090000004a00000000")
    let counter = 1'u32
    var ctx = Chacha20()
    ctx.init(key, nonce, counter)
    ctx.chacha20Block()

    var byteOutput: array[64, byte]
    ctx.extractKeyStreamBlock(byteOutput)
    var serializedOutput = toHex(byteOutput)
    check:
      serializedOutput == expectedHexOutput

  test "Chacha20 encrypt example text":
    let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let nonce = fromHex("000000000000004a00000000") # note: the 4th byte of the nonce is "00" and not "09" opposed to previous tests
    let counter = 1'u32
    ## even if you don't mutate plaintext, it needs to be *var* if you want to access its addr (for memcopy)
    var plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    let expectedCipherTextBytes = "6E2E359A2568F98041BA0728DD0D6981E97E7AEC1D4360C20A27AFCCFD9FAE0BF91B65C5524733AB8F593DABCD62B3571639D624E65152AB8F530C359F0861D807CA0DBF500D6A6156A38E088A22B65E52BC514D16CCF806818CE91AB77937365AF90BBF74A35BE6B40B8EEDF2785E42874D"
    let expectedCipherText = """n.5.%h..A..(..i..~z..C`..'........e.RG3..Y=..b.W.9.$.QR..S.5..a.....P.jaV....".^R.QM.........y76Z...t.[......x^B"""
    var plainTextBytes = newSeq[byte](len(plaintext))
    var cipherTextBytes = newSeq[byte](len(plaintext))
    copyMem(addr plainTextBytes[0], addr plaintext[0], len(plaintext))
    chacha20Encrypt(key, counter, nonce, plainTextBytes, cipherTextBytes)
    check:
      toHex(cipherTextBytes) == expectedCipherTextBytes
    var cipherText = toString(cipherTextBytes)

    # check:
      # RFC uses ASCII encoding
      # cipherText == expectedCipherText

  test "Chacha20 encrypt & decrpyt": # non RFC
    let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let nonce = fromHex("000000000000004a00000000") # note: the 4th byte of the nonce is "00" and not "09" opposed to previous tests
    let counter = 1'u32
    var plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    var plainTextBytes = newSeq[byte](len(plaintext))
    var cipherTextBytes = newSeq[byte](len(plaintext))
    var decryptedTextBytes = newSeq[byte](len(plaintext))
    copyMem(addr plainTextBytes[0], addr plaintext[0], len(plaintext))
    chacha20Encrypt(key, counter, nonce, plainTextBytes, cipherTextBytes)
    chacha20Decrypt(key, counter, nonce, cipherTextBytes, decryptedTextBytes)
    check:
      plainTextBytes == decryptedTextBytes
  
  test "Chacha20 encrypt & decrypt file": # non RFC
    let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let nonce = fromHex("000000000000004a00000000") # note: the 4th byte of the nonce is "00" and not "09" opposed to previous tests
    let counter = 1'u32
    chacha20EncryptFile(key, counter, nonce, "chacha_plain.txt", "chacha_cipher.txt")
    chacha20DecryptFile(key, counter, nonce, "chacha_cipher.txt", "chacha_plain-dec.txt")
    check:
      readFile("chacha_plain.txt") == readFile("chacha_plain-dec.txt")
    removeFile("chacha_cipher.txt")
    removeFile("chacha_plain-dec.txt")

  # test "Chacha20 encrypt & decrypt file long": # non RFC
  #   let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  #   let nonce = fromHex("000000000000004a00000000") # note: the 4th byte of the nonce is "00" and not "09" opposed to previous tests
  #   let counter = 1'u32
  #   chacha20EncryptFile(key, counter, nonce, "faust.txt", "faust.enc")
  #   chacha20DecryptFile(key, counter, nonce, "faust.enc", "faust.dec")
  #   check:
  #     readFile("faust.txt") == readFile("faust.dec")

  # test "Chacha20 encrypt & decrypt jpg": # non RFC
  #   let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  #   let nonce = fromHex("000000000000004a00000000") # note: the 4th byte of the nonce is "00" and not "09" opposed to previous tests
  #   let counter = 1'u32
  #   chacha20EncryptFile(key, counter, nonce, "test.jpg", "test.jpg.enc")
  #   chacha20DecryptFile(key, counter, nonce, "test.jpg.enc", "test-dec.jpg")
  #   check:
  #     readFile("test.jpg") == readFile("test-dec.jpg")


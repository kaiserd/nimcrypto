## tests input from rfc8439
## further tests are marked with (non RFC)

import system

import nimcrypto/utils
import ../nimcrypto/chacha # you need to "nimble install" to add libs to the search path
import unittest

suite "chacha  tests":

  test "chacha basic operations":
      var a = 0x11111111'u32
      var b = 0x01020304'u32
      var c = 0x77777777'u32
      var d = 0x01234567'u32
      c = c + d
      b = b xor c
      check:
        c == 0x789abcde'u32 # wrapping add is default in Nim
        b == 0x7998bfda'u32
      b = ROL(b,7)
      check:
        b == 0xcc5fed3c'u32

  test "quater round standallone":
    var a = 0x11111111'u32
    var b = 0x01020304'u32
    var c = 0x9b8d6f43'u32
    var d = 0x01234567'u32
    (a,b,c,d) = quater_round_standallone(a, b, c, d);
    check:
      a == 0xea2a92f4'u32
      b == 0xcb1cf8ce'u32
      c == 0x4581472e'u32
      d == 0x5881c4bb'u32

  test "quater round":
    var state_input = [
      0x879531e0'u32,  0xc5ecf37d'u32,  0x516461b1'u32,  0xc9a62f8a'u32,
      0x44c20ef3'u32,  0x3390af7f'u32,  0xd9fc690b'u32,  0x2a5f714c'u32,
      0x53372767'u32,  0xb00a5631'u32,  0x974c541a'u32,  0x359e9963'u32,
      0x5c971061'u32,  0x3d631689'u32,  0x2098d9d6'u32,  0x91dbd320'u32,
    ]
    var state_expected_result =  [
      0x879531e0'u32,  0xc5ecf37d'u32,  0xbdb886dc'u32,  0xc9a62f8a'u32,
      0x44c20ef3'u32,  0x3390af7f'u32,  0xd9fc690b'u32,  0xcfacafd2'u32,
      0xe46bea80'u32,  0xb00a5631'u32,  0x974c541a'u32,  0x359e9963'u32,
      0x5c971061'u32,  0xccc07c79'u32,  0x2098d9d6'u32,  0x91dbd320'u32,
    ]
    var chacha_ctx = Chacha20()
    chacha_ctx.init(state_input)
    chacha_ctx.quater_round(2, 7, 8, 13)
    check:
      chacha_ctx.state == state_expected_result


  test "block 20 rounds":
    var state_input = [ # contains key
      0x61707865'u32,  0x3320646e'u32,  0x79622d32'u32,  0x6b206574'u32,
      0x03020100'u32,  0x07060504'u32,  0x0b0a0908'u32,  0x0f0e0d0c'u32,
      0x13121110'u32,  0x17161514'u32,  0x1b1a1918'u32,  0x1f1e1d1c'u32,
      0x00000001'u32,  0x09000000'u32,  0x4a000000'u32,  0x00000000'u32,
    ]
    var state_expected_result = [
      0x837778ab'u32,  0xe238d763'u32,  0xa67ae21e'u32,  0x5950bb2f'u32,
      0xc4f2d0c7'u32,  0xfc62bb2f'u32,  0x8fa018fc'u32,  0x3f5ec7b7'u32,
      0x335271c2'u32,  0xf29489f3'u32,  0xeabda8fc'u32,  0x82e46ebd'u32,
      0xd19c12b4'u32,  0xb04e16de'u32,  0x9e83d0cb'u32,  0x4e3c50a2'u32,
    ]
    var chacha_ctx = Chacha20()
    chacha_ctx.init(state_input)
    chacha_ctx.chacha20_block()
    check:
      chacha_ctx.state == state_expected_result

  test "block 20 rounds & add original state":
    var state_input = [
      0x61707865'u32,  0x3320646e'u32,  0x79622d32'u32,  0x6b206574'u32,
      0x03020100'u32,  0x07060504'u32,  0x0b0a0908'u32,  0x0f0e0d0c'u32,
      0x13121110'u32,  0x17161514'u32,  0x1b1a1918'u32,  0x1f1e1d1c'u32,
      0x00000001'u32,  0x09000000'u32,  0x4a000000'u32,  0x00000000'u32,
    ]
    var state_expected_result = [
      0xe4e7f110'u32,  0x15593bd1'u32,  0x1fdd0f50'u32,  0xc47120a3'u32,
      0xc7f4d1c7'u32,  0x0368c033'u32,  0x9aaa2204'u32,  0x4e6cd4c3'u32,
      0x466482d2'u32,  0x09aa9f07'u32,  0x05d7c214'u32,  0xa2028bd9'u32,
      0xd19c12b5'u32,  0xb94e16de'u32,  0xe883d0cb'u32,  0x4e3c50a2'u32,
    ]
    var chacha_ctx = Chacha20()
    chacha_ctx.init(state_input)
    chacha_ctx.chacha20_block()
    chacha_ctx.add_original_state()
    check:
      chacha_ctx.state == state_expected_result

  test "reset and increment counter (non RFC)":
    var state_input = [
      0x61707865'u32,  0x3320646e'u32,  0x79622d32'u32,  0x6b206574'u32,
      0x03020100'u32,  0x07060504'u32,  0x0b0a0908'u32,  0x0f0e0d0c'u32,
      0x13121110'u32,  0x17161514'u32,  0x1b1a1918'u32,  0x1f1e1d1c'u32,
      0x00000001'u32,  0x09000000'u32,  0x4a000000'u32,  0x00000000'u32,
    ]
    var state_expected_result = [
      0x61707865'u32,  0x3320646e'u32,  0x79622d32'u32,  0x6b206574'u32,
      0x03020100'u32,  0x07060504'u32,  0x0b0a0908'u32,  0x0f0e0d0c'u32,
      0x13121110'u32,  0x17161514'u32,  0x1b1a1918'u32,  0x1f1e1d1c'u32,
      0x00000002'u32,  0x09000000'u32,  0x4a000000'u32,  0x00000000'u32,
    ]
    var chacha_ctx = Chacha20()
    chacha_ctx.init(state_input)
    chacha_ctx.chacha20_block() # do 20 chacha rounds to mix the state
    chacha_ctx.add_original_state()
    chacha_ctx.reset_state_and_increment_counter()
    check:
      chacha_ctx.original_state == state_expected_result
      chacha_ctx.state          == state_expected_result

  test "setup state":
    var state_input = [
      0x61707865'u32,  0x3320646e'u32,  0x79622d32'u32,  0x6b206574'u32,
      0x03020100'u32,  0x07060504'u32,  0x0b0a0908'u32,  0x0f0e0d0c'u32,
      0x13121110'u32,  0x17161514'u32,  0x1b1a1918'u32,  0x1f1e1d1c'u32,
      0x00000001'u32,  0x09000000'u32,  0x4a000000'u32,  0x00000000'u32,
    ]
    let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let nonce = fromHex("000000090000004a00000000")
    let counter = 1'u32
    var chacha_ctx = Chacha20()
    chacha_ctx.init(key, nonce, counter)
    check:
      chacha_ctx.original_state == state_input
      chacha_ctx.state          == state_input

  test "setup state & block 20 rounds & add original state":
    var state_expected_result = [
      0xe4e7f110'u32,  0x15593bd1'u32,  0x1fdd0f50'u32,  0xc47120a3'u32,
      0xc7f4d1c7'u32,  0x0368c033'u32,  0x9aaa2204'u32,  0x4e6cd4c3'u32,
      0x466482d2'u32,  0x09aa9f07'u32,  0x05d7c214'u32,  0xa2028bd9'u32,
      0xd19c12b5'u32,  0xb94e16de'u32,  0xe883d0cb'u32,  0x4e3c50a2'u32,
    ]
    let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let nonce = fromHex("000000090000004a00000000")
    let counter = 1'u32
    var chacha_ctx = Chacha20()
    chacha_ctx.init(key, nonce, counter)
    chacha_ctx.chacha20_block()
    chacha_ctx.add_original_state()
    check:
      chacha_ctx.state == state_expected_result

  test "state export, serialized output":
    var expected_hex_output = "10F1E7E4D13B5915500FDD1FA32071C4C7D1F4C733C068030422AA9AC3D46C4ED2826446079FAA0914C2D705D98B02A2B5129CD1DE164EB9CBD083E8A2503C4E"
    let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let nonce = fromHex("000000090000004a00000000")
    let counter = 1'u32
    var chacha_ctx = Chacha20()
    chacha_ctx.init(key, nonce, counter)
    chacha_ctx.chacha20_block()
    chacha_ctx.add_original_state()

    var byte_output: array[64, byte]
    chacha_ctx.export_state_bytes(byte_output)
    var serialized_output = toHex(byte_output)
    check:
      serialized_output == expected_hex_output

  test "encrypt example text":
    let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let nonce = fromHex("000000000000004a00000000") # note: the 4th byte of the nonce is "00" and not "09" opposed to previous tests
    let counter = 1'u32
    ## even if you don't mutate plaintext, it needs to be *var* if you want to access its addr (for memcopy)
    var plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    let expected_cipher_text_bytes = "6E2E359A2568F98041BA0728DD0D6981E97E7AEC1D4360C20A27AFCCFD9FAE0BF91B65C5524733AB8F593DABCD62B3571639D624E65152AB8F530C359F0861D807CA0DBF500D6A6156A38E088A22B65E52BC514D16CCF806818CE91AB77937365AF90BBF74A35BE6B40B8EEDF2785E42874D"
    let expected_cipher_text = """n.5.%h..A..(..i..~z..C`..'........e.RG3..Y=..b.W.9.$.QR..S.5..a.....P.jaV....".^R.QM.........y76Z...t.[......x^B"""
    var plain_text_bytes = newSeq[byte](len(plaintext))
    var cipher_text_bytes = newSeq[byte](len(plaintext))
    copyMem(addr plain_text_bytes[0], addr plaintext[0], len(plaintext))
    chacha20_encrypt(key, counter, nonce, plain_text_bytes, cipher_text_bytes)
    check:
      toHex(cipherTextBytes) == expected_cipher_text_bytes
    var cipher_text = toString(cipher_text_bytes)

    # check:
      # thy use different encoding
      # cipher_text == expected_cipher_text

  test "encrypt & decrpyt (non RFC)":
    let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let nonce = fromHex("000000000000004a00000000") # note: the 4th byte of the nonce is "00" and not "09" opposed to previous tests
    let counter = 1'u32
    var plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    var plain_text_bytes = newSeq[byte](len(plaintext))
    var cipher_text_bytes = newSeq[byte](len(plaintext))
    var decrypted_text_bytes = newSeq[byte](len(plaintext))
    copyMem(addr plain_text_bytes[0], addr plaintext[0], len(plaintext))
    chacha20_encrypt(key, counter, nonce, plain_text_bytes, cipher_text_bytes)
    chacha20_decrypt(key, counter, nonce, cipher_text_bytes, decrypted_text_bytes)
    check:
      plain_text_bytes == decrypted_text_bytes
  
  test "encrypt & decrypt files (non RFC)":
    let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    let nonce = fromHex("000000000000004a00000000") # note: the 4th byte of the nonce is "00" and not "09" opposed to previous tests
    let counter = 1'u32
    chacha20_encrypt_file(key, counter, nonce, "plaintext", "ciphertext")
    chacha20_decrypt_file(key, counter, nonce, "ciphertext", "plaintext_dec")
    check:
      readFile("plaintext") == readFile("plaintext_dec")

  # test "encrypt & decrypt file long (non RFC)":
  #   let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  #   let nonce = fromHex("000000000000004a00000000") # note: the 4th byte of the nonce is "00" and not "09" opposed to previous tests
  #   let counter = 1'u32
  #   chacha20_encrypt_file(key, counter, nonce, "faust.txt", "faust.enc")
  #   chacha20_decrypt_file(key, counter, nonce, "faust.enc", "faust.dec")
  #   check:
  #     readFile("faust.txt") == readFile("faust.dec")

  # test "encrypt & decrypt jpg (non RFC)":
  #   let key   = fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
  #   let nonce = fromHex("000000000000004a00000000") # note: the 4th byte of the nonce is "00" and not "09" opposed to previous tests
  #   let counter = 1'u32
  #   chacha20_encrypt_file(key, counter, nonce, "test.jpg", "test.jpg.enc")
  #   chacha20_decrypt_file(key, counter, nonce, "test.jpg.enc", "test-dec.jpg")
  #   check:
  #     readFile("test.jpg") == readFile("test-dec.jpg")


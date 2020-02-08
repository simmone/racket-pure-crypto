#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../../src/cipher/aes/key-expansion.rkt")

(define test-key-expansion
  (test-suite
   "test-key-expansion"
   
   (test-case
    "test-rcon"
    
    (check-equal? (rcon 1) "01")
    (check-equal? (rcon 2) "02")
    (check-equal? (rcon 3) "04")
    (check-equal? (rcon 4) "08")
    (check-equal? (rcon 5) "10")
    (check-equal? (rcon 6) "20")
    (check-equal? (rcon 7) "40")
    (check-equal? (rcon 8) "80")
    (check-equal? (rcon 9) "1b")
    (check-equal? (rcon 10) "36"))

   (test-case
    "test-aes-128-key-expansion"

    (check-equal? 
     (key-expansion "2b7e151628aed2a6abf7158809cf4f3c" 4 10)
     '("2b7e151628aed2a6abf7158809cf4f3c"
       "a0fafe1788542cb123a339392a6c7605"
       "f2c295f27a96b9435935807a7359f67f"
       "3d80477d4716fe3e1e237e446d7a883b"
       "ef44a541a8525b7fb671253bdb0bad00"
       "d4d1c6f87c839d87caf2b8bc11f915bc"
       "6d88a37a110b3efddbf98641ca0093fd"
       "4e54f70e5f5fc9f384a64fb24ea6dc4f"
       "ead27321b58dbad2312bf5607f8d292f"
       "ac7766f319fadc2128d12941575c006e"
       "d014f9a8c9ee2589e13f0cc8b6630ca6"
       )))

    (check-equal? 
     (key-expansion "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b" 6 12)
     '("8e73b0f7da0e6452c810f32b809079e5"
       "62f8ead2522c6b7bfe0c91f72402f5a5"
       "ec12068e6c827f6b0e7a95b95c56fec2"
       "4db7b4bd69b5411885a74796e92538fd"
       "e75fad44bb095386485af05721efb14f"
       "a448f6d94d6dce24aa326360113b30e6"
       "a25e7ed583b1cf9a27f939436a94f767"
       "c0a69407d19da4e1ec1786eb6fa64971"
       "485f703222cb8755e26d135233f0b7b3"
       "40beeb282f18a2596747d26b458c553e"
       "a7e1466c9411f1df821f750aad07d753"
       "ca4005388fcc5006282d166abc3ce7b5"
       "e98ba06f448c773c8ecc720401002202"))

    (check-equal? 
     (key-expansion "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4" 8 14)
     '("603deb1015ca71be2b73aef0857d7781"
       "1f352c073b6108d72d9810a30914dff4"
       "9ba354118e6925afa51a8b5f2067fcde"
       "a8b09c1a93d194cdbe49846eb75d5b9a"
       "d59aecb85bf3c917fee94248de8ebe96"
       "b5a9328a2678a647983122292f6c79b3"
       "812c81addadf48ba24360af2fab8b464"
       "98c5bfc9bebd198e268c3ba709e04214"
       "68007bacb2df331696e939e46c518d80" 
       "c814e20476a9fb8a5025c02d59c58239"
       "de1369676ccc5a71fa2563959674ee15"
       "5886ca5d2e2f31d77e0af1fa27cf73c3"
       "749c47ab18501ddae2757e4f7401905a"
       "cafaaae3e4d59b349adf6acebd10190d"
       "fe4890d1e6188d0b046df344706c631e"))

    (check-equal? 
     (key-expansion "000102030405060708090a0b0c0d0e0f" 4 10)
     '("000102030405060708090a0b0c0d0e0f"
       "d6aa74fdd2af72fadaa678f1d6ab76fe"
       "b692cf0b643dbdf1be9bc5006830b3fe"
       "b6ff744ed2c2c9bf6c590cbf0469bf41"
       "47f7f7bc95353e03f96c32bcfd058dfd"
       "3caaa3e8a99f9deb50f3af57adf622aa"
       "5e390f7df7a69296a7553dc10aa31f6b"
       "14f9701ae35fe28c440adf4d4ea9c026"
       "47438735a41c65b9e016baf4aebf7ad2"
       "549932d1f08557681093ed9cbe2c974e"
       "13111d7fe3944a17f307a78b4d2b30c5"))

   ))

(run-tests test-key-expansion)

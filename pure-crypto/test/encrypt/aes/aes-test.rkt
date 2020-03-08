#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../../src/encrypt.rkt")

(define test-encrypt
  (test-suite
   "test-encrypt"

   (test-case
    "test-ecb-128"


    (check-equal?
     (encrypt #:cipher? 'aes "0123456789ABCDEF0123456789ABCDEF" "133457799BBCDFF133457799BBCDFFAB"
              #:operation_mode? 'ecb #:data_format? 'hex #:key_format? 'hex)
     "4AE08C70BEA1D25577F34EF92877F787"
    )

    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'ecb #:data_format? 'hex #:key_format? 'hex
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "2b7e151628aed2a6abf7158809cf4f3c")
     (string-append
      "3AD77BB40D7A3660A89ECAF32466EF97"
      "F5D3D58503B9699DE785895A96FDBAAF"
      "43B1CD7F598ECE23881B00E3ED030688"
      "7B0C785E27E8AD3F8223207104725DD4")
     )

    )
   
   (test-case
    "test-cbc-128"

    (check-equal?
     (encrypt #:cipher? 'aes "chenxiaoxiaochen" "chensihehesichen")
     "3C0AEADD704C4A2FF227CCB67C2F4F65")

    (check-equal?
     (encrypt #:cipher? 'aes "a" "chensihehesichen")
     "260C2109180E3B4DE5211ADB02660079")
    
    (check-equal?
     (encrypt #:cipher? 'aes "a" "chensihehesichen")
     "260C2109180E3B4DE5211ADB02660079")

    (check-equal?
     (encrypt #:cipher? 'aes "chenxiaoxiaochena" "chensihehesichen")
     "3C0AEADD704C4A2FF227CCB67C2F4F65368558C041C2FDA8B8A6084D9D8AC03A")

    (check-equal?
     (encrypt #:cipher? 'aes #:iv? "fffffffffffffffffffffffffffffff0" "chenxiaoxiaochen" "chensihehesichen")
     "47CB10ECCA531AAA564B1FEC30483407")

    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex
              #:iv? "000102030405060708090a0b0c0d0e0f"
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "2B7E151628AED2A6ABF7158809CF4F3C")
     (string-append
      "7649ABAC8119B246CEE98E9B12E9197D"
      "5086CB9B507219EE95DB113A917678B2"
      "73BED6B8E3C1743B7116E69E22229516"
      "3FF1CAA1681FAC09120ECA307586E1A7"))
    )

   (test-case
    "test-ecb-192"

    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'ecb
              "0123456789ABCDEF0123456789ABCDEF"
              "133457799BBCDFF133457799BBCDFFAB0123456789ABCDEF")
     "C326C015F55309BCD0A6219107969FF0")

    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'ecb
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")

     (string-append
      "BD334F1D6E45F25FF712A214571FA5CC"
      "974104846D0AD3AD7734ECB3ECEE4EEF"
      "EF7AFD2270E2E60ADCE0BA2FACE6444E"
      "9A4B41BA738D6C72FB16691603C18E0E"))

    (check-equal?
     (encrypt #:cipher? 'aes "chenxiaoxiaochen" "chensihehesichenxiaochen")
     "4925EA049EB1129593CDA1C980EBFD41")

    (check-equal?
     (encrypt #:cipher? 'aes "a" "chensihehesichenxiaochen")
     "1A5DF9AB8B6D5278A3859029FBD7305D")

    )

   (test-case
    "test-cbc-192"

    (check-equal?
     (encrypt #:cipher? 'aes "a" "chensihehesichenxiaochen")
     "1A5DF9AB8B6D5278A3859029FBD7305D")

    (check-equal?
     (encrypt #:cipher? 'aes "chenxiaoxiaochena" "chensihehesichenxiaochen")
     "4925EA049EB1129593CDA1C980EBFD41BF4A3CD4210F6A6614100F2311A67CA6")

    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex
              #:iv? "000102030405060708090a0b0c0d0e0f"
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B")
     (string-append
      "4F021DB243BC633D7178183A9FA071E8"
      "B4D9ADA9AD7DEDF4E5E738763F69145A"
      "571B242012FB7AE07FA9BAAC3DF102E0"
      "08B0E27988598881D920A9E64F5615CD"))

    )

   (test-case
    "test-cbc-256"

    (check-equal?
     (encrypt #:cipher? 'aes "chenxiaoxiaochena" "chensihehesichenxiaochenchenxiao")
     "2F1E5BC38EC4736B6D5CCA79859B95BE401410A3BB8E9CDB2507D667DDA81DD1"
     )

    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex
              #:iv? "000102030405060708090a0b0c0d0e0f"
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4")
     (string-append
      "F58C4C04D6E5F1BA779EABFB5F7BFBD6"
      "9CFC4E967EDB808D679F777BC6702C7D"
      "39F23369A9D9BACFA530E26304231461"
      "B2EB05E2C39BE9FCDA6C19078C6A9D1B"))

    )
   
   (test-case
    "test-ecb-256"

    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'ecb "chenxiaoxiaochena" "chensihehesichenxiaochenchenxiao")
     "2F1E5BC38EC4736B6D5CCA79859B95BE29AD707A840DE8F8F69F17C609DA85EA"
     )

    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'ecb #:data_format? 'hex #:key_format? 'hex
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
     (string-append
      "F3EED1BDB5D2A03C064B5A7E3DB181F8"
      "591CCB10D410ED26DC5BA74A31362870"
      "B6ED21B99CA6F4F9F153E7B1BEAFED1D"
      "23304B7A39F9F3FF067D8D8F9E24ECC7"))
    )

   (test-case
    "test-ofb-128"
    
    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'ofb
              "chenxiaoxiaochena" "chensihehesichen")
     "D8308E159E56ED0B24811CE4DF1E0CDB54")

    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'ofb
              #:iv? "000102030405060708090a0b0c0d0e0f"
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "2B7E151628AED2A6ABF7158809CF4F3C")
     (string-append
      "3B3FD92EB72DAD20333449F8E83CFB4A"
      "7789508D16918F03F53C52DAC54ED825"
      "9740051E9C5FECF64344F7A82260EDCC"
      "304C6528F659C77866A510D9C1D6AE5E"))

    )
   
   (test-case
    "test-ofb-192"

    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'ofb
              #:iv? "000102030405060708090a0b0c0d0e0f"
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
     (string-append
      "CDC80D6FDDF18CAB34C25909C99A4174"
      "FCC28B8D4C63837C09E81700C1100401"
      "8D9A9AEAC0F6596F559C6D4DAF59A5F2"
      "6D9F200857CA6C3E9CAC524BD9ACC92A"))

    )

   (test-case
    "test-ofb-256"

    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'ofb
              #:iv? "000102030405060708090a0b0c0d0e0f"
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
     (string-append
      "DC7E84BFDA79164B7ECD8486985D3860"
      "4FEBDC6740D20B3AC88F6AD82A4FB08D"
      "71AB47A086E86EEDF39D1C5BBA97C408"
      "0126141D67F37BE8538F5A8BE740E484"))

    )

   (test-case
    "test-cfb-128"
    
    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'cfb
              "chenxiaoxiaochena" "chensihehesichen")
     "D8308E159E56ED0B24811CE4DF1E0CDBDF")

    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'cfb
              #:iv? "000102030405060708090a0b0c0d0e0f"
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "2B7E151628AED2A6ABF7158809CF4F3C")
     (string-append
      "3B3FD92EB72DAD20333449F8E83CFB4A"
      "C8A64537A0B3A93FCDE3CDAD9F1CE58B"
      "26751F67A3CBB140B1808CF187A4F4DF"
      "C04B05357C5D1C0EEAC4C66F9FF7F2E6"))
    )
   
   (test-case
    "test-cfb-192"

    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'cfb
              #:iv? "000102030405060708090a0b0c0d0e0f"
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B")
     (string-append
      "CDC80D6FDDF18CAB34C25909C99A4174"
      "67CE7F7F81173621961A2B70171D3D7A"
      "2E1E8A1DD59B88B1C8E60FED1EFAC4C9"
      "C05F9F9CA9834FA042AE8FBA584B09FF"))
    )
   
   (test-case
    "test-cfb-256"

     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'cfb
              #:iv? "000102030405060708090a0b0c0d0e0f"
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4")
     (string-append
      "DC7E84BFDA79164B7ECD8486985D3860"
      "39FFED143B28B1C832113C6331E5407B"
      "DF10132415E54B92A13ED0A8267AE2F9"
      "75A385741AB9CEF82031623D55B1E471")
   )

   (test-case
    "test-pcbc-128"
    
    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'pcbc
              "chenxiaoxiaochena" "chensihehesichen")
    "3C0AEADD704C4A2FF227CCB67C2F4F6502C1F73B805A0C031741F9F0D9B6CBFD")
    )

   (test-case
    "test-ctr-128"
    
    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'ctr
              #:iv? "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "2B7E151628AED2A6ABF7158809CF4F3C")
     (string-append
      "874D6191B620E3261BEF6864990DB6CE"
      "9806F66B7970FDFF8617187BB9FFFDFF"
      "5AE4DF3EDBD5D35E5B4F09020DB03EAB"
      "1E031DDA2FBE03D1792170A0F3009CEE"))
    )

   ))

 (run-tests test-encrypt)

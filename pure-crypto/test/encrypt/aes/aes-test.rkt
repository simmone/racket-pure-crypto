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
     "4ae08c70bea1d25577f34ef92877f787"
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
      "3ad77bb40d7a3660a89ecaf32466ef97"
      "f5d3d58503b9699de785895a96fdbaaf"
      "43b1cd7f598ece23881b00e3ed030688"
      "7b0c785e27e8ad3f8223207104725dd4")
     )

    )

   (test-case
    "test-ecb-192"

    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'ecb
              "0123456789ABCDEF0123456789ABCDEF"
              "133457799BBCDFF133457799BBCDFFAB0123456789ABCDEF")
     "c326c015f55309bcd0a6219107969ff0")

    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'ecb
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")

     (string-append
      "bd334f1d6e45f25ff712a214571fa5cc"
      "974104846d0ad3ad7734ecb3ecee4eef"
      "ef7afd2270e2e60adce0ba2face6444e"
      "9a4b41ba738d6c72fb16691603c18e0e"))

    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'ecb
              "chenxiaoxiaochen" "chensihehesichenxiaochen")
     "4925ea049eb1129593cda1c980ebfd41")

    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'ecb
              "a" "chensihehesichenxiaochen")
     "1a5df9ab8b6d5278a3859029fbd7305d")

    )

   (test-case
    "test-ecb-256"

    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'ecb "chenxiaoxiaochena" "chensihehesichenxiaochenchenxiao")
     "2f1e5bc38ec4736b6d5cca79859b95be29ad707a840de8f8f69f17c609da85ea"
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
      "f3eed1bdb5d2a03c064b5a7e3db181f8"
      "591ccb10d410ed26dc5ba74a31362870"
      "b6ed21b99ca6f4f9f153e7b1beafed1d"
      "23304b7a39f9f3ff067d8d8f9e24ecc7"))
    )

   (test-case
    "test-cbc-128"

    (check-equal?
     (encrypt #:cipher? 'aes "chenxiaoxiaochen" "chensihehesichen")
     "3c0aeadd704c4a2ff227ccb67c2f4f65")

    (check-equal?
     (encrypt #:cipher? 'aes "a" "chensihehesichen")
     "260c2109180e3b4de5211adb02660079")
    
    (check-equal?
     (encrypt #:cipher? 'aes "a" "chensihehesichen")
     "260c2109180e3b4de5211adb02660079")

    (check-equal?
     (encrypt #:cipher? 'aes "chenxiaoxiaochena" "chensihehesichen")
     "3c0aeadd704c4a2ff227ccb67c2f4f65368558c041c2fda8b8a6084d9d8ac03a")

    (check-equal?
     (encrypt #:cipher? 'aes #:iv? "fffffffffffffffffffffffffffffff0" "chenxiaoxiaochen" "chensihehesichen")
     "47cb10ecca531aaa564b1fec30483407")

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
      "7649abac8119b246cee98e9b12e9197d"
      "5086cb9b507219ee95db113a917678b2"
      "73bed6b8e3c1743b7116e69e22229516"
      "3ff1caa1681fac09120eca307586e1a7"))
    )

   (test-case
    "test-cbc-192"

    (check-equal?
     (encrypt #:cipher? 'aes "a" "chensihehesichenxiaochen")
     "1a5df9ab8b6d5278a3859029fbd7305d")

    (check-equal?
     (encrypt #:cipher? 'aes "chenxiaoxiaochena" "chensihehesichenxiaochen")
     "4925ea049eb1129593cda1c980ebfd41bf4a3cd4210f6a6614100f2311a67ca6")

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
      "4f021db243bc633d7178183a9fa071e8"
      "b4d9ada9ad7dedf4e5e738763f69145a"
      "571b242012fb7ae07fa9baac3df102e0"
      "08b0e27988598881d920a9e64f5615cd"))

    )

   (test-case
    "test-cbc-256"

    (check-equal?
     (encrypt #:cipher? 'aes "chenxiaoxiaochena" "chensihehesichenxiaochenchenxiao")
     "2f1e5bc38ec4736b6d5cca79859b95be401410a3bb8e9cdb2507d667dda81dd1"
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
      "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
      "9cfc4e967edb808d679f777bc6702c7d"
      "39f23369a9d9bacfa530e26304231461"
      "b2eb05e2c39be9fcda6c19078c6a9d1b"))

    )
   
   (test-case
    "test-ofb-128"
    
    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'ofb
              "chenxiaoxiaochena" "chensihehesichen")
     "d8308e159e56ed0b24811ce4df1e0cdb54")

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
      "3b3fd92eb72dad20333449f8e83cfb4a"
      "7789508d16918f03f53c52dac54ed825"
      "9740051e9c5fecf64344f7a82260edcc"
      "304c6528f659c77866a510d9c1d6ae5e"))

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
      "cdc80d6fddf18cab34c25909c99a4174"
      "fcc28b8d4c63837c09e81700c1100401"
      "8d9a9aeac0f6596f559c6d4daf59a5f2"
      "6d9f200857ca6c3e9cac524bd9acc92a"))

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
      "dc7e84bfda79164b7ecd8486985d3860"
      "4febdc6740d20b3ac88f6ad82a4fb08d"
      "71ab47a086e86eedf39d1c5bba97c408"
      "0126141d67f37be8538f5a8be740e484"))

    )

   (test-case
    "test-cfb-128"
    
    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'cfb
              "chenxiaoxiaochena" "chensihehesichen")
     "d8308e159e56ed0b24811ce4df1e0cdbdf")

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
      "3b3fd92eb72dad20333449f8e83cfb4a"
      "c8a64537a0b3a93fcde3cdad9f1ce58b"
      "26751f67a3cbb140b1808cf187a4f4df"
      "c04b05357c5d1c0eeac4c66f9ff7f2e6"))
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
      "cdc80d6fddf18cab34c25909c99a4174"
      "67ce7f7f81173621961a2b70171d3d7a"
      "2e1e8a1dd59b88b1c8e60fed1efac4c9"
      "c05f9f9ca9834fa042ae8fba584b09ff"))
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
      "dc7e84bfda79164b7ecd8486985d3860"
      "39ffed143b28b1c832113c6331e5407b"
      "df10132415e54b92a13ed0a8267ae2f9"
      "75a385741ab9cef82031623d55b1e471")
   )

   (test-case
    "test-pcbc-128"
    
    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'pcbc
              "chenxiaoxiaochena" "chensihehesichen")
    "3c0aeadd704c4a2ff227ccb67c2f4f6502c1f73b805a0c031741f9f0d9b6cbfd")
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
      "874d6191b620e3261bef6864990db6ce"
      "9806f66b7970fdff8617187bb9fffdff"
      "5ae4df3edbd5d35e5b4f09020db03eab"
      "1e031dda2fbe03d1792170a0f3009cee"))
    )

   (test-case
    "test-ctr-192"
    
    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'ctr
              #:iv? "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B")
     (string-append
      "1abc932417521ca24f2b0459fe7e6e0b"
      "090339ec0aa6faefd5ccc2c6f4ce8e94"
      "1e36b26bd1ebc670d1bd1d665620abf7"
      "4f78a7f6d29809585a97daec58c6b050"))
    )

   (test-case
    "test-ctr-256"
    
    (check-equal?
     (encrypt #:cipher? 'aes #:key_format? 'hex #:data_format? 'hex #:operation_mode? 'ctr
              #:iv? "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
              (string-append
               "6bc1bee22e409f96e93d7e117393172a"
               "ae2d8a571e03ac9c9eb76fac45af8e51"
               "30c81c46a35ce411e5fbc1191a0a52ef"
               "f69f2445df4f9b17ad2b417be66c3710")
              "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
     (string-append
      "601ec313775789a5b7a7f504bbf3d228"
      "f443e3ca4d62b59aca84e990cacaf5c5"
      "2b0930daa23de94ce87017ba2d84988d"
      "dfc9c58db67aada613c2dd08457941a6"))
    )

   ))

 (run-tests test-encrypt)

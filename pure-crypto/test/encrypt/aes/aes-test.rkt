#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../../src/encrypt.rkt")

(define test-encrypt
  (test-suite
   "test-encrypt"

   ;; AES-ECB-128
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
   
   ;; TEXT-CASE: CBC-128 PlAIN:PLAIN:HEX
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
     (encrypt #:cipher? 'aes #:iv? "0ffffffffffffffffffffffffffffff0" "chenxiaoxiaochen" "chensihehesichen")
     "763B31EA992109C7D7DC9A3D8BE8D65C")
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

    )

   (test-case
    "test-cbc-256"

    (check-equal?
     (encrypt #:cipher? 'aes "chenxiaoxiaochena" "chensihehesichenxiaochenchenxiao")
     "2F1E5BC38EC4736B6D5CCA79859B95BE401410A3BB8E9CDB2507D667DDA81DD1"
     )
    )
   
   (test-case
    "test-ecb-256"

    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'ecb "chenxiaoxiaochena" "chensihehesichenxiaochenchenxiao")
     "2F1E5BC38EC4736B6D5CCA79859B95BE29AD707A840DE8F8F69F17C609DA85EA"
     )
    )

   (test-case
    "test-ofb-128"
    
    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'ofb
              "chenxiaoxiaochena" "chensihehesichen")
     "D8308E159E56ED0B24811CE4DF1E0CDB54")
    )

   (test-case
    "test-cfb-128"
    
    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'cfb
              "chenxiaoxiaochena" "chensihehesichen")
     "D8308E159E56ED0B24811CE4DF1E0CDBDF")
    )

   (test-case
    "test-pcbc-128"
    
    (check-equal?
     (encrypt #:cipher? 'aes #:operation_mode? 'pcbc
              "chenxiaoxiaochena" "chensihehesichen")
    "3C0AEADD704C4A2FF227CCB67C2F4F6502C1F73B805A0C031741F9F0D9B6CBFD")
    )

   ))

 (run-tests test-encrypt)

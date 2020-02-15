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
     (encrypt #:cipher? 'aes "chenxiaoxiaochen" "chensihehesichen")
     "3C0AEADD704C4A2FF227CCB67C2F4F65")

    (check-equal?
     (encrypt #:cipher? 'aes "a" "chensihehesichen")
     "260C2109180E3B4DE5211ADB02660079")
    )
   
   (test-case
    "test-cbc-128"
    
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
              "0123456789ABCDEF0123456789ABCDEF" "133457799BBCDFF133457799BBCDFFAB0123456789ABCDEF")
     "C326C015F55309BCD0A6219107969FF0")

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

   ))

 (run-tests test-encrypt)

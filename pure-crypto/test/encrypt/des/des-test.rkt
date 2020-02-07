#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../../src/encrypt.rkt")

(define test-encrypt
  (test-suite
   "test-encrypt"

   (test-case
    "test-ecb"

    (check-exn
     exn:fail?
     (lambda ()
       (encrypt "chenxiao" "陈晓陈晓陈晓" #:operation_mode? 'ecb)))

    (check-exn
     exn:fail?
     (lambda ()
       (encrypt "0123456789ABCDEF" "133457799BBCDFF" #:operation_mode? 'ecb #:data_format? 'hex #:key_format? 'hex)))

    (check-equal? 
     (encrypt "chenxiao" "chensihe" #:operation_mode? 'ecb)
     "E99DAFFBF097826E")

    (check-equal? 
     (encrypt "chenxiaoxiaochenxichaoen" "chensihe" #:operation_mode? 'ecb)
     "E99DAFFBF097826E5869CD2F437912B1512861DF0C737B6A")

    (check-equal? 
     (encrypt "0123456789ABCDEF" "133457799BBCDFF1" #:data_format? 'hex #:key_format? 'hex #:operation_mode? 'ecb)
     "85E813540F0AB405")

    (check-equal? 
     (encrypt "ASNFZ4mrze8=\r\n" "EzRXeZu83/E=\r\n" #:data_format? 'base64 #:key_format? 'base64 #:operation_mode? 'ecb)
     "85E813540F0AB405")

    (check-equal? 
     (encrypt "a" "chensihe" #:operation_mode? 'ecb)
     "92165495EDA4824D")

    (check-equal? 
     (encrypt "a" "chensihe" #:padding_mode? 'zero #:operation_mode? 'ecb)
     "F1794BC1714BD236")
    )

   (test-case
    "test-cbc"

    (check-equal? 
     (encrypt "a" "chensihe")
     "92165495EDA4824D")

    (check-equal? 
     (encrypt "a" "chensihe" #:padding_mode? 'zero)
     "F1794BC1714BD236")

    (check-equal? 
     (encrypt "chenxiaoa" "chensihe")
     "E99DAFFBF097826E1759A70DF5A7E1D0")

    (check-equal? 
     (encrypt "chenxiaoxiaochen" "chensihe")
     "E99DAFFBF097826E560E22D458A0A6B7")

    (check-equal?
     (encrypt "chenxiaoxiaochenxichaoen" "chensihe" #:iv? "0000000000000000")
     "E99DAFFBF097826E560E22D458A0A6B74E619B140E43A94F")

    (check-equal? 
     (encrypt "a" "chensihe" #:iv? "fffffffffffffff0")
     "624EE363AF4BFC4F")

    (check-equal? 
     (encrypt "chenxiaoxiaochenxichaoen" "chensihe" #:iv? "0000000000000000")
     "E99DAFFBF097826E560E22D458A0A6B74E619B140E43A94F")

    (check-equal? 
     (encrypt "chenxiaoxiaochenxichaoen" "chensihe" #:iv? "fffffffffffffff0")
    "275B51E2D3DDD76BA629E7ECFB0C03A883157C6D56457DC2")

    (check-equal? 
     (encrypt "chenxiaochenminchentianzhen" "chensihe" #:iv? "fffffffffffffff0")
     "275B51E2D3DDD76B02A658F4C0EB72D00B0129D3BB9120AFDE698C458D1EE949")
    )

   (test-case
    "test-pcbc"
    
    (check-equal?
     (encrypt "6368656e7869616f6368656e6d696e6368656e7469616e7a68656e"
          "98623ecd8520d64f"
          #:data_format? 'hex
          #:key_format? 'hex
          #:operation_mode? 'pcbc
          #:iv? "86dae6d37a7c8a34"
          )
     "EEAC09D9E2E536B80DF9F7EAB91061874A7CA00903C64184B9EAAEF5A4718C49")
    )

   (test-case
    "test-cfb"

    (check-equal? 
     (encrypt
      "chenxiaochenminchentianzhen" "chensihe" #:operation_mode? 'cfb #:iv? "fffffffffffffff0")
     "7EA6157895C0B609DCC7A9645569EC06AABBAB0517748203CE5F8B")
    )

   (test-case
    "test-ofb"

    (check-equal? 
     (encrypt "chenxiaochenminchentianzhen" "chensihe" #:operation_mode? 'ofb #:iv? "fffffffffffffff0")
     "7EA6157895C0B609B6CE2D3CB48D37648EB2798508C8B8A8E6F8B9"
    )
    )

   ))

 (run-tests test-encrypt)

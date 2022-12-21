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
    ;; DES key length is invalid. expect 16/32/48(hex), but get 36

    (check-exn
     exn:fail?
     (lambda ()
       (encrypt "0123456789ABCDEF" "133457799BBCDFF" #:operation_mode? 'ecb #:data_format? 'hex #:key_format? 'hex)))
    ;; DES key length is invalid. expect 16/32/48(hex), but get 15

    (check-equal? 
     (encrypt "chenxiao" "chensihe" #:operation_mode? 'ecb)
     "e99daffbf097826e")

    (check-equal? 
     (encrypt "chenxiaoxiaochenxichaoen" "chensihe" #:operation_mode? 'ecb)
     "e99daffbf097826e5869cd2f437912b1512861df0c737b6a")

    (check-equal? 
     (encrypt "0123456789ABCDEF" "133457799BBCDFF1" #:data_format? 'hex #:key_format? 'hex #:operation_mode? 'ecb)
     "85e813540f0ab405")

    (check-equal? 
     (encrypt "ASNFZ4mrze8=\r\n" "EzRXeZu83/E=\r\n" #:data_format? 'base64 #:key_format? 'base64 #:operation_mode? 'ecb)
     "85e813540f0ab405")

    (check-equal? 
     (encrypt "a" "chensihe" #:operation_mode? 'ecb)
     "92165495eda4824d")

    (check-equal? 
     (encrypt "a" "chensihe" #:padding_mode? 'zero #:operation_mode? 'ecb)
     "f1794bc1714bd236")
    )

   (test-case
    "test-cbc"

    (check-equal? 
     (encrypt "a" "chensihe")
     "92165495eda4824d")

    (check-equal? 
     (encrypt "a" "chensihe" #:padding_mode? 'zero)
     "f1794bc1714bd236")

    (check-equal? 
     (encrypt "chenxiaoa" "chensihe")
     "e99daffbf097826e1759a70df5a7e1d0")

    (check-equal? 
     (encrypt "chenxiaoxiaochen" "chensihe")
     "e99daffbf097826e560e22d458a0a6b7")

    (check-equal?
     (encrypt "chenxiaoxiaochenxichaoen" "chensihe" #:iv? "0000000000000000")
     "e99daffbf097826e560e22d458a0a6b74e619b140e43a94f")

    (check-equal? 
     (encrypt "a" "chensihe" #:iv? "fffffffffffffff0")
     "624ee363af4bfc4f")

    (check-equal? 
     (encrypt "chenxiaoxiaochenxichaoen" "chensihe" #:iv? "0000000000000000")
     "e99daffbf097826e560e22d458a0a6b74e619b140e43a94f")

    (check-equal? 
     (encrypt "chenxiaoxiaochenxichaoen" "chensihe" #:iv? "fffffffffffffff0")
    "275b51e2d3ddd76ba629e7ecfb0c03a883157c6d56457dc2")

    (check-equal? 
     (encrypt "chenxiaochenminchentianzhen" "chensihe" #:iv? "fffffffffffffff0")
     "275b51e2d3ddd76b02a658f4c0eb72d00b0129d3bb9120afde698c458d1ee949")
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
     "eeac09d9e2e536b80df9f7eab91061874a7ca00903c64184b9eaaef5a4718c49")
    )

   (test-case
    "test-cfb"

    (check-equal? 
     (encrypt
      "chenxiaochenminchentianzhen" "chensihe" #:operation_mode? 'cfb #:iv? "fffffffffffffff0")
     "7ea6157895c0b609dcc7a9645569ec06aabbab0517748203ce5f8b")
    )

   (test-case
    "test-ofb"

    (check-equal? 
     (encrypt "chenxiaochenminchentianzhen" "chensihe" #:operation_mode? 'ofb #:iv? "fffffffffffffff0")
     "7ea6157895c0b609b6ce2d3cb48d37648eb2798508c8b8a8e6f8b9"
    )
    )

   ))

 (run-tests test-encrypt)

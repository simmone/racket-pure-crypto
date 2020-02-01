#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../src/undes.rkt")

(define test-des
  (test-suite
   "test-des"

   (test-case
    "test-ecb"

    (check-equal? 
     (undes
      "E99DAFFBF097826E"
      "chensihe"
      #:operation_mode? 'ecb
      )
      "chenxiao"
     )

    (check-equal? 
     (undes
      "85E813540F0AB405"
      "133457799BBCDFF1" #:operation_mode? 'ecb #:data_format? 'hex #:key_format? 'hex)
      "0123456789ABCDEF"
     )

    (check-equal? 
     (undes
     "85E813540F0AB405"
     "EzRXeZu83/E=\r\n" #:data_format? 'base64 #:key_format? 'base64 #:operation_mode? 'ecb)
     "ASNFZ4mrze8=\r\n"
     )

    (check-equal? 
     (undes
     "92165495EDA4824D"
      "chensihe"
      #:operation_mode? 'ecb)
     "a"
     )

    (check-equal? 
     (undes
     "F1794BC1714BD236"
      "chensihe" #:padding_mode? 'zero #:operation_mode? 'ecb)
      "a"
     )
    )

   (test-case
    "test-cbc"

    (check-equal? 
     (undes
      "92165495EDA4824D"
      "chensihe"
      )
     "a"
     )

    (check-equal? 
     (undes
      "624EE363AF4BFC4F"
      "chensihe" #:iv? "fffffffffffffff0"
      )
      "a"
     )

    (check-equal? 
     (undes
      "275B51E2D3DDD76B02A658F4C0EB72D00B0129D3BB9120AFDE698C458D1EE949"
      "chensihe" #:iv? "fffffffffffffff0"
      )
     "chenxiaochenminchentianzhen"
     )
    )

   (test-case
    "test-pcbc"
    
    (check-equal?
     (undes
      "EEAC09D9E2E536B80DF9F7EAB91061874A7CA00903C64184B9EAAEF5A4718C49"
      "98623ecd8520d64f"
      #:data_format? 'hex
      #:key_format? 'hex
      #:operation_mode? 'pcbc
      #:iv? "86dae6d37a7c8a34"
      )
     "6368656E7869616F6368656E6D696E6368656E7469616E7A68656E"
     )
    )

   (test-case
    "test-cfb"

    (check-equal? 
     (undes
      "7EA6157895C0B609DCC7A9645569EC06AABBAB0517748203CE5F8B"
      "chensihe" #:operation_mode? 'cfb #:iv? "fffffffffffffff0"
      )
      "chenxiaochenminchentianzhen"
     )
    )

   (test-case
    "test-ofb"

    (check-equal? 
     (undes
     "7EA6157895C0B609B6CE2D3CB48D37648EB2798508C8B8A8E6F8B9"
     "chensihe" #:operation_mode? 'ofb #:iv? "fffffffffffffff0")
     "chenxiaochenminchentianzhen"
    )
    )

   ))

(run-tests test-des)

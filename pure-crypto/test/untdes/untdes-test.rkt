#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../src/untdes.rkt")

(define test-untdes
  (test-suite
   "test-untdes"

   (test-case
    "test-ecb"

    (check-equal? 
     (untdes
      "803B74B5ABD02C32"
      "chensihehesichenchenhesi" #:operation_mode? 'ecb)
      "chenxiao")

    (check-equal?
     (untdes
      "803B74B5ABD02C32CAC5C68DD6F9B705"
      "chensihehesichenchenhesi" #:operation_mode? 'ecb #:padding_mode? 'zero)
      "chenxiaoa")

    (check-equal? 
     (untdes
      "60F46BC94F680177"
      "ceensihehepichenchenhes`" #:operation_mode? 'ecb)
     "chenxiao")

    (check-equal? 
     (untdes
      "2D61506C375C685E"
      "133457799BBCDFF1134357799BBCDFF1133547799BBCDFF1" #:data_format? 'hex #:key_format? 'hex #:operation_mode? 'ecb)
      "0123456789ABCDEF")

    (check-equal? 
     (untdes
      "803B74B5ABD02C32"
      "Y2hlbnNpaGVoZXNpY2hlbmNoZW5oZXNp\r\n" #:data_format? 'base64 #:key_format? 'base64 #:operation_mode? 'ecb)
     "Y2hlbnhpYW8=\r\n")

    (check-equal? 
     (untdes
      "CAC5C68DD6F9B705"
      "chensihehesichenchenhesi" #:padding_mode? 'zero #:operation_mode? 'ecb)
      "a")
    )

   (test-case
    "test-cbc"

    (check-equal? 
     (untdes
      "6AE1861FBD926B64"
      "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:padding_mode? 'zero)
     "a")

    (check-equal? 
     (untdes
      "E99DAFFBF097826E560E22D458A0A6B74E619B140E43A94F"
      "chensihechensihechensihe" #:iv? "0000000000000000")
      "chenxiaoxiaochenxichaoen")

    (check-equal?
     (untdes
      "803B74B5ABD02C32"
      "chensihehesichenchenhesi" #:iv? "0000000000000000" #:padding_mode? 'zero)
      "chenxiao")

    (check-equal?
     (untdes
      "803B74B5ABD02C32"
      "chensihehesichenchenhesi" #:iv? "0000000000000000")
      "chenxiao")

    (check-equal?
     (untdes
      "1C3E33D251887902"
      "chensihehesichenchenhesi" #:iv? "0000000000000000")
      "xiaochen")

    (check-equal?
     (untdes
      "803B74B5ABD02C32"
      "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "chenxiao")

    (check-equal?
     (untdes
      "1C3E33D251887902"
      "chensihehesichenchenhesi" #:iv? "0000000000000000")
      "xiaochen")

    (check-equal?
     (untdes
      "803B74B5ABD02C328193178A1A7F5800"
      "chensihehesichenchenhesi" #:iv? "0000000000000000")
      "chenxiaoxiaochen")

    (check-equal?
     (untdes
      "803B74B5ABD02C328193178A1A7F5800FB0518C9F08FF02A"
      "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "chenxiaoxiaochenxichaoen")
    )

   (test-case
    "test-cfb"

    (check-equal?
     (untdes
      "CA"
      "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'cfb)
      "a")

    (check-equal?
     (untdes
      "C84F774F93392FD0"
      "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'cfb)
     "chenxiao")

    (check-equal?
     (untdes
      "C84F774F93392FD01C"
      "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'cfb)
     "chenxiaoa")

    (check-equal?
     (untdes
      "C84F774F93392FD01EA83A04A5D03102F5D7"
      "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'cfb)
     "chenxiaochensiheng")

    )

   (test-case
    "test-ofb"

    (check-equal?
     (untdes
      "CA"
      "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'ofb)
      "a")

    (check-equal?
     (untdes
      "C84F774F93392FD0"
      "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'ofb)
      "chenxiao")

    (check-equal?
     (untdes
      "C84F774F93392FD0B3"
      "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'ofb)
     "chenxiaoa")

    (check-equal?
     (untdes
      "C84F774F93392FD0B1AC57402FC6A01B28D7"
      "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'ofb)
     "chenxiaochensiheng")
    )

   ))

(run-tests test-untdes)

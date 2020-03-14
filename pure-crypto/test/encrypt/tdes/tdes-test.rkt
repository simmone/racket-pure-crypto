#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../../src/encrypt.rkt")

(define test-tdes
  (test-suite
   "test-tdes"

   (test-case
    "test-ecb"

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiao" "陈晓陈晓陈晓" #:operation_mode? 'ecb)
     #f)

    (check-equal?
     (encrypt #:cipher? 'tdes "0123456789ABCDEF" "133457799BBCDFF" #:operation_mode? 'ecb #:data_format? 'hex #:key_format? 'hex)
     #f)

    (check-equal? 
     (encrypt #:cipher? 'tdes #:operation_mode? 'ecb
              "chenxiao" "chensihehesichenchenhesi"
              )
     "803b74b5abd02c32")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaoa" "chensihehesichenchenhesi" #:operation_mode? 'ecb #:padding_mode? 'zero)
     "803b74b5abd02c32cac5c68dd6f9b705")

    (check-equal? 
     (encrypt #:cipher? 'tdes "chenxiao" "ceensihehepichenchenhes`" #:operation_mode? 'ecb)
     "60f46bc94f680177")

    (check-equal? 
     (encrypt #:cipher? 'tdes "0123456789ABCDEF" "133457799BBCDFF1134357799BBCDFF1133547799BBCDFF1" #:data_format? 'hex #:key_format? 'hex #:operation_mode? 'ecb)
     "2d61506c375c685e")

    (check-equal? 
     (encrypt #:cipher? 'tdes "Y2hlbnhpYW8=\r\n" "Y2hlbnNpaGVoZXNpY2hlbmNoZW5oZXNp\r\n" #:data_format? 'base64 #:key_format? 'base64 #:operation_mode? 'ecb)
     "803b74b5abd02c32")

    (check-equal? 
     (encrypt #:cipher? 'tdes "a" "chensihehesichenchenhesi" #:padding_mode? 'zero #:operation_mode? 'ecb)
     "cac5c68dd6f9b705")

    )

   (test-case
    "test-cbc"

    (check-equal?
     (encrypt #:cipher? 'tdes "a" "chensihehesichenchenhesi" #:iv? "000000000000000")
     #f)

    (check-equal? 
     (encrypt #:cipher? 'tdes "a" "chensihehesichenchenhesi")
     "41e4496d46c8f5be")

    (check-equal? 
     (encrypt #:cipher? 'tdes "a" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:padding_mode? 'zero)
     "6ae1861fbd926b64")

    (check-equal? 
     (encrypt #:cipher? 'tdes "chenxiaoxiaochenxichaoen" "chensihechensihechensihe" #:iv? "0000000000000000")
     "e99daffbf097826e560e22d458a0a6b74e619b140e43a94f")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiao" "chensihehesichenchenhesi" #:iv? "0000000000000000" #:padding_mode? 'zero)
     "803b74b5abd02c32")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiao" "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "803b74b5abd02c32")

    (check-equal?
     (encrypt #:cipher? 'tdes "xiaochen" "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "1c3e33d251887902")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiao" "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "803b74b5abd02c32")

    (check-equal?
     (encrypt #:cipher? 'tdes "xiaochen" "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "1c3e33d251887902")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaoxiaochen" "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "803b74b5abd02c328193178a1a7f5800")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaoxiaochenxichaoen" "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "803b74b5abd02c328193178a1a7f5800fb0518c9f08ff02a")
    )

   (test-case
    "test-cfb"

    (check-equal?
     (encrypt #:cipher? 'tdes #:iv? "fffffffffffffff0" #:operation_mode? 'cfb #:detail? '("detail1.pdf")
              "a" "chensihehesichenchenhesi")
     "ca")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiao" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'cfb)
     "c84f774f93392fd0")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaoa" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'cfb)
     "c84f774f93392fd01c")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaochensiheng" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'cfb)
     "c84f774f93392fd01ea83a04a5d03102f5d7")
    )

   (test-case
    "test-ofb"

    (check-equal?
     (encrypt #:cipher? 'tdes "a" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'ofb)
     "ca")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiao" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'ofb)
     "c84f774f93392fd0")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaoa" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'ofb)
     "c84f774f93392fd0b3")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaochensiheng" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'ofb)
     "c84f774f93392fd0b1ac57402fc6a01b28d7")

    )

   ))

(run-tests test-tdes)

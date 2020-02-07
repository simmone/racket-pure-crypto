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
     (encrypt #:cipher? 'tdes "chenxiao" "chensihehesichenchenhesi" #:operation_mode? 'ecb)
     "803B74B5ABD02C32")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaoa" "chensihehesichenchenhesi" #:operation_mode? 'ecb #:padding_mode? 'zero)
     "803B74B5ABD02C32CAC5C68DD6F9B705")

    (check-equal? 
     (encrypt #:cipher? 'tdes "chenxiao" "ceensihehepichenchenhes`" #:operation_mode? 'ecb)
     "60F46BC94F680177")

    (check-equal? 
     (encrypt #:cipher? 'tdes "0123456789ABCDEF" "133457799BBCDFF1134357799BBCDFF1133547799BBCDFF1" #:data_format? 'hex #:key_format? 'hex #:operation_mode? 'ecb)
     "2D61506C375C685E")

    (check-equal? 
     (encrypt #:cipher? 'tdes "Y2hlbnhpYW8=\r\n" "Y2hlbnNpaGVoZXNpY2hlbmNoZW5oZXNp\r\n" #:data_format? 'base64 #:key_format? 'base64 #:operation_mode? 'ecb)
     "803B74B5ABD02C32")

    (check-equal? 
     (encrypt #:cipher? 'tdes "a" "chensihehesichenchenhesi" #:padding_mode? 'zero #:operation_mode? 'ecb)
     "CAC5C68DD6F9B705")

    )

   (test-case
    "test-cbc"

    (check-equal?
     (encrypt #:cipher? 'tdes "a" "chensihehesichenchenhesi" #:iv? "000000000000000")
     #f)

    (check-equal? 
     (encrypt #:cipher? 'tdes "a" "chensihehesichenchenhesi")
     "41E4496D46C8F5BE")

    (check-equal? 
     (encrypt #:cipher? 'tdes "a" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:padding_mode? 'zero)
     "6AE1861FBD926B64")

    (check-equal? 
     (encrypt #:cipher? 'tdes "chenxiaoxiaochenxichaoen" "chensihechensihechensihe" #:iv? "0000000000000000")
     "E99DAFFBF097826E560E22D458A0A6B74E619B140E43A94F")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiao" "chensihehesichenchenhesi" #:iv? "0000000000000000" #:padding_mode? 'zero)
     "803B74B5ABD02C32")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiao" "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "803B74B5ABD02C32")

    (check-equal?
     (encrypt #:cipher? 'tdes "xiaochen" "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "1C3E33D251887902")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiao" "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "803B74B5ABD02C32")

    (check-equal?
     (encrypt #:cipher? 'tdes "xiaochen" "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "1C3E33D251887902")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaoxiaochen" "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "803B74B5ABD02C328193178A1A7F5800")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaoxiaochenxichaoen" "chensihehesichenchenhesi" #:iv? "0000000000000000")
     "803B74B5ABD02C328193178A1A7F5800FB0518C9F08FF02A")
    )

   (test-case
    "test-cfb"

    (check-equal?
     (encrypt #:cipher? 'tdes "a" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'cfb)
     "CA")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiao" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'cfb)
     "C84F774F93392FD0")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaoa" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'cfb)
     "C84F774F93392FD01C")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaochensiheng" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'cfb)
     "C84F774F93392FD01EA83A04A5D03102F5D7")
    )

   (test-case
    "test-ofb"

    (check-equal?
     (encrypt #:cipher? 'tdes "a" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'ofb)
     "CA")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiao" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'ofb)
     "C84F774F93392FD0")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaoa" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'ofb)
     "C84F774F93392FD0B3")

    (check-equal?
     (encrypt #:cipher? 'tdes "chenxiaochensiheng" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:operation_mode? 'ofb)
     "C84F774F93392FD0B1AC57402FC6A01B28D7")

    )

   ))

(run-tests test-tdes)

#lang racket

(require des)

;; des/undes ecb
(des "chenxiao" "chensihe" #:operation_mode? 'ecb) ;; "E99DAFFBF097826E"
(undes "E99DAFFBF097826E" "chensihe" #:operation_mode? 'ecb) ;; "chenxiao"

;; des/undes ecb data_format: base64 key_format: base64
(des "ASNFZ4mrze8=\r\n" "EzRXeZu83/E=\r\n" #:data_format? 'base64 #:key_format? 'base64 #:operation_mode? 'ecb) ;; "85E813540F0AB405"
(undes "85E813540F0AB405" "EzRXeZu83/E=\r\n" #:data_format? 'base64 #:key_format? 'base64 #:operation_mode? 'ecb) ;; "ASNFZ4mrze8=\r\n"

;; des/undes cbc
(des "a" "chensihe" #:iv? "fffffffffffffff0")  ;; "624EE363AF4BFC4F"
(undes "624EE363AF4BFC4F" "chensihe" #:iv? "fffffffffffffff0")  ;; "a"

;; tdes/untdes ecb
(tdes "chenxiao" "chensihehesichenchenhesi" #:operation_mode? 'ecb) ;; "803B74B5ABD02C32"
(untdes "803B74B5ABD02C32" "chensihehesichenchenhesi" #:operation_mode? 'ecb) ;; "chenxiao"

;; tdes/untdes cbc
(tdes "a" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:padding_mode? 'zero) ;; "6AE1861FBD926B64"
(untdes "6AE1861FBD926B64" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:padding_mode? 'zero) ;; "a"






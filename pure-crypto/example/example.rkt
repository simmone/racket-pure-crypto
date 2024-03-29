#lang racket

(require "../main.rkt")

;; des/undes cbc
(encrypt "a" "chensihe") ;; "92165495eda4824d"
(decrypt "92165495eda4824d" "chensihe") ;; "a"

;; des/undes ecb data_format: base64 key_format: base64
(encrypt "ASNFZ4mrze8=\r\n" "EzRXeZu83/E=\r\n" #:data_format? 'base64 #:key_format? 'base64 #:operation_mode? 'ecb) ;; "85e813540f0ab405"
(decrypt "85E813540F0AB405" "EzRXeZu83/E=\r\n" #:data_format? 'base64 #:key_format? 'base64 #:operation_mode? 'ecb) ;; "ASNFZ4mrze8=\r\n"

;; tdes/untdes cbc
(encrypt #:cipher? 'tdes "chenxiaoxiaochenxichaoen" "chensihechensihechensihe" #:iv? "0000000000000000") ;; "e99daffbf097826e560e22d458a0a6b74e619b140e43a94f")
(decrypt #:cipher? 'tdes "e99daffbf097826e560e22d458a0a6b74e619b140e43a94f" "chensihechensihechensihe" #:iv? "0000000000000000") ;; "chenxiaoxiaochenxichaoen")

;; tdes/untdes with padding_mode
(encrypt #:cipher? 'tdes "a" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:padding_mode? 'zero) ;; "6ae1861fbd926b64"
(decrypt #:cipher? 'tdes "6ae1861fbd926b64" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:padding_mode? 'zero) ;; "a"

;; aes/unaes cbc
(encrypt #:cipher? 'aes "chenxiaoxiaochen" "chensihehesichen") ;; "3c0aeadd704c4a2ff227ccb67c2f4f65"
(decrypt #:cipher? 'aes "3c0aeadd704c4a2ff227ccb67c2f4f65" "chensihehesichen") ;; "chenxiaoxiaochen"








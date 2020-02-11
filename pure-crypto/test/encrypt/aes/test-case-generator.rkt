#lang racket

(require "../../openssl/openssl.rkt")

(printf "~a\n" (openssl 'hex "enc -aes-128-ecb -nopad -nosalt" "0123456789ABCDEF0123456789ABCDEF" "133457799BBCDFF133457799BBCDFFAB"))

;(printf "~a\n" (openssl 'plain "enc -des-ecb -nopad -nosalt" "chenxiao" "chensihe"))
;
;(printf "~a\n" (openssl 'plain "enc -des-ecb -nopad -nosalt" "chenxiaoxiaochenxichaoen" "chensihe"))
;
;(printf "~a\n" (openssl 'plain "enc -des-ecb -nosalt" "a" "chensihe"))
;
;(printf "~a\n" (openssl 'plain "enc -des-cbc -nosalt -iv 0000000000000000" "a" "chensihe"))
;
;(printf "~a\n" (openssl 'plain "enc -des-cbc -nosalt -iv 0000000000000000" "chenxiaoa" "chensihe"))
;
;(printf "~a\n" (openssl 'plain "enc -des-cbc -nosalt -iv 0000000000000000" "chenxiaoxiaochenxichaoen" "chensihe"))
;
;(printf "~a\n" (openssl 'plain "enc -des-cbc -nosalt -nopad -iv 0000000000000000" "chenxiaoxiaochenxichaoen" "chensihe"))
;
;(printf "~a\n" (openssl 'plain "enc -des-cbc -nosalt -nopad -iv fffffffffffffff0" "chenxiaoxiaochenxichaoen" "chensihe"))
;
;(printf "~a\n" (openssl 'plain "enc -des-cbc -nosalt -iv fffffffffffffff0" "a" "chensihe"))
;
;(printf "~a\n" (openssl 'plain "enc -des-cbc -nosalt -iv fffffffffffffff0" "chenxiaochenminchentianzhen" "chensihe"))
;
;(printf "~a\n" (openssl 'plain "enc -des-cfb -nosalt -iv fffffffffffffff0" "chenxiaochenminchentianzhen" "chensihe"))
;
;(printf "~a\n" (openssl 'plain "enc -des-ofb -nosalt -iv fffffffffffffff0" "chenxiaochenminchentianzhen" "chensihe"))


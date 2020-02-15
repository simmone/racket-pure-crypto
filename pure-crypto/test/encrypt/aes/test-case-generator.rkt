#lang racket

(require "../../openssl/openssl.rkt")

(printf "~a\n" (openssl 'hex "enc -aes-128-ecb -nopad -nosalt" "0123456789ABCDEF0123456789ABCDEF" "133457799BBCDFF133457799BBCDFFAB"))

(printf "~a\n" (openssl 'plain "enc -aes-128-ecb -nopad -nosalt" "chenxiaoxiaochen" "chensihehesichen"))

(printf "~a\n" (openssl 'plain "enc -aes-128-ecb -nosalt" "a" "chensihehesichen"))

(printf "~a\n" (openssl 'plain "enc -aes-128-cbc -nosalt -iv 00000000000000000000000000000000" "a" "chensihehesichen"))

(printf "~a\n" (openssl 'plain "enc -aes-128-cbc -nosalt -iv 00000000000000000000000000000000" "chenxiaoxiaochena" "chensihehesichen"))

(printf "~a\n" (openssl 'plain "enc -aes-128-cbc -nosalt -nopad -iv fffffffffffffffffffffffffffffff0" "chenxiaoxiaochen" "chensihehesichen"))

(printf "~a\n" (openssl 'plain "enc -aes-128-cbc -nosalt -nopad -iv 0ffffffffffffffffffffffffffffff0" "chenxiaoxiaochen" "chensihehesichen"))

(printf "~a\n" (openssl 'hex "enc -aes-192-ecb -nopad -nosalt" "0123456789ABCDEF0123456789ABCDEF" "133457799BBCDFF133457799BBCDFFAB0123456789ABCDEF"))

(printf "~a\n" (openssl 'plain "enc -aes-192-ecb -nopad -nosalt" "chenxiaoxiaochen" "chensihehesichenxiaochen"))

(printf "~a\n" (openssl 'plain "enc -aes-192-ecb -nosalt" "a" "chensihehesichenxiaochen"))

(printf "~a\n" (openssl 'plain "enc -aes-192-cbc -nosalt -iv 00000000000000000000000000000000" "a" "chensihehesichenxiaochen"))

(printf "~a\n" (openssl 'plain "enc -aes-192-cbc -nosalt -iv 00000000000000000000000000000000" "chenxiaoxiaochena" "chensihehesichenxiaochen"))

#lang racket

(require "../openssl/openssl.rkt")

(printf "~a\n" (openssl 'plain "enc -des-ede3 -nosalt -nopad -iv 0000000000000000" "chenxiao" "chensihehesichenchenhesi"))

(printf "~a\n" (openssl 'plain "enc -des-ede3-cbc -nosalt -nopad -iv 0000000000000000" "chenxiaoxiaochen" "chensihehesichenchenhesi"))
(printf "~a\n" (openssl 'plain "enc -des-ede3-cbc -nosalt -nopad -iv 0000000000000000" "chenxiaoxiaochenxichaoen" "chensihehesichenchenhesi"))

(printf "~a\n" (openssl 'plain "enc -des-ede3-cfb -nosalt -iv fffffffffffffff0" "a" "chensihehesichenchenhesi"))
(printf "~a\n" (openssl 'plain "enc -des-ede3-cfb -nosalt -iv fffffffffffffff0" "chenxiao" "chensihehesichenchenhesi"))
(printf "~a\n" (openssl 'plain "enc -des-ede3-cfb -nosalt -iv fffffffffffffff0" "chenxiaoa" "chensihehesichenchenhesi"))
(printf "~a\n" (openssl 'plain "enc -des-ede3-cfb -nosalt -iv fffffffffffffff0" "chenxiaochensiheng" "chensihehesichenchenhesi"))

(printf "~a\n" (openssl 'plain "enc -des-ede3-ofb -nosalt -iv fffffffffffffff0" "a" "chensihehesichenchenhesi"))
(printf "~a\n" (openssl 'plain "enc -des-ede3-ofb -nosalt -iv fffffffffffffff0" "chenxiao" "chensihehesichenchenhesi"))
(printf "~a\n" (openssl 'plain "enc -des-ede3-ofb -nosalt -iv fffffffffffffff0" "chenxiaoa" "chensihehesichenchenhesi"))
(printf "~a\n" (openssl 'plain "enc -des-ede3-ofb -nosalt -iv fffffffffffffff0" "chenxiaochensiheng" "chensihehesichenchenhesi"))



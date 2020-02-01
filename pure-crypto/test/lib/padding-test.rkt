#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../src/lib/padding.rkt")

(define test-padding
  (test-suite
   "test-padding"

   (test-case
    "test-pkcs5"

    (check-equal? 
     (padding-pkcs5 "0102030405060708" 64)
     "0102030405060708")

    (check-equal? 
     (padding-pkcs5 "01020304050607" 64)
     "0102030405060701")

    (check-equal? 
     (padding-pkcs5 "010203040506" 64)
     "0102030405060202")

    (check-equal? 
     (padding-pkcs5 "010203" 64)
     "0102030505050505")

    (check-equal? 
     (padding-pkcs5 "61" 64)
     "6107070707070707")

    (check-equal? 
     (unpadding-pkcs5 "6107070707070707" 64)
      "61")

    (check-equal? 
     (unpadding-pkcs5 "0102030405060708" 64)
     "0102030405060708")

    (check-equal? 
     (unpadding-pkcs5 "0102030405060701" 64)
     "01020304050607")

    (check-equal? 
     (unpadding-pkcs5 "0102030405060202" 64)
     "010203040506")

    (check-equal? 
     (unpadding-pkcs5 "0102030505050505" 64)
     "010203")

    (check-equal? 
     (unpadding-pkcs5 "010203050505050505" 64)
     "01020305")

    (check-equal? 
     (unpadding-pkcs5 "01020305050505" 64)
     "01020305050505")

    )

   (test-case
    "test-zero"

    (check-equal? 
     (padding-zero "0102030405060708" 64)
     "0102030405060708")

    (check-equal? 
     (padding-zero "01020304050607" 64)
     "0102030405060700")

    (check-equal? 
     (padding-zero "010203040506" 64)
     "0102030405060000")

    (check-equal? 
     (unpadding-zero "0102030405060708" 64)
     "0102030405060708")

    (check-equal? 
     (unpadding-zero "0102030405060700" 64)
     "01020304050607")

    (check-equal? 
     (unpadding-zero "0102030405060000" 64)
     "010203040506")
    )

   (test-case
    "test-ansix923"

    (check-equal? 
     (padding-ansix923 "0102030405060708" 64)
     "0102030405060708")

    (check-equal? 
     (padding-ansix923 "01020304050607" 64)
     "0102030405060701")

    (check-equal? 
     (padding-ansix923 "DDDDDDDD" 64)
     "DDDDDDDD00000004")

    (check-equal? 
     (padding-ansix923 "" 64)
     "0000000000000008")

    (check-equal? 
     (unpadding-ansix923 "0102030405060708" 64)
     "0102030405060708")

    (check-equal? 
     (unpadding-ansix923 "0102030405060701" 64)
     "01020304050607")

    (check-equal? 
     (unpadding-ansix923 "DDDDDDDD00000004" 64)
     "DDDDDDDD")

    (check-equal? 
     (unpadding-ansix923 "0000000000000008" 64)
     "")
    )

   (test-case
    "test-iso10126"

    (check-equal? 
     (padding-iso10126 "0102030405060708" 64)
     "0102030405060708")

    (check-equal? 
     (padding-iso10126 "01020304050607" 64)
     "0102030405060701")

    (check-equal? 
     (substring
      (padding-iso10126 "DDDDDDDD" 64)
      14 16)
     "04")

    (check-equal?
     (substring
      (padding-iso10126 "" 64)
      14 16)
     "08")

    (check-equal? 
     (unpadding-iso10126 "0102030405060709" 64)
     "0102030405060709")

    (check-equal? 
     (unpadding-iso10126 "0102030405060701" 64)
     "01020304050607")

    (check-equal? 
     (unpadding-iso10126 "DDDDDDDD02FF0C04" 64)
     "DDDDDDDD")

    (check-equal? 
     (unpadding-iso10126 "0F0D0E0100030408" 64)
     "")
    )
  
   ))

(run-tests test-padding)

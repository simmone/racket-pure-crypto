#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../src/lib/padding.rkt")

(define test-padding
  (test-suite
   "test-padding"

   (test-case
    "test-pkcs7"

    (check-equal? 
     (padding-pkcs7 "0102030405060708" 64)
     "0102030405060708")

    (check-equal? 
     (padding-pkcs7 "0102030405060708" 128)
     "01020304050607080808080808080808")

    (check-equal? 
     (padding-pkcs7 "01" 64)
     "0107070707070707")

    (check-equal? 
     (padding-pkcs7 "01" 128)
     "010f0f0f0f0f0f0f0f0f0f0f0f0f0f0f")

    (check-equal? 
     (padding-pkcs7 "010203040506" 64)
     "0102030405060202")

    (check-equal? 
     (padding-pkcs7 "010203" 64)
     "0102030505050505")

    (check-equal? 
     (padding-pkcs7 "61" 64)
     "6107070707070707")

    (check-equal? 
     (unpadding-pkcs7 "6107070707070707" 64)
      "61")

    (check-equal? 
     (unpadding-pkcs7 "01020304050607080808080808080808" 128)
     "0102030405060708")

    (check-equal? 
     (unpadding-pkcs7 "010f0f0f0f0f0f0f0f0f0f0f0f0f0f0f" 128)
     "01")

    (check-equal? 
     (unpadding-pkcs7 "610F0F0F0F0F0F0F0F0F0F0F0F0F0F0F" 128)
     "61")

    (check-equal? 
     (unpadding-pkcs7 "0102030405060708" 64)
     "0102030405060708")

    (check-equal? 
     (unpadding-pkcs7 "0102030405060701" 64)
     "01020304050607")

    (check-equal? 
     (unpadding-pkcs7 "0102030405060202" 64)
     "010203040506")

    (check-equal? 
     (unpadding-pkcs7 "0102030505050505" 64)
     "010203")

    (check-equal? 
     (unpadding-pkcs7 "010203050505050505" 64)
     "01020305")

    (check-equal? 
     (unpadding-pkcs7 "01020305050505" 64)
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
     (padding-zero "0102030405060708" 128)
     "01020304050607080000000000000000")

    (check-equal? 
     (unpadding-zero "01020304050607080000000000000000" 128)
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
     (padding-ansix923 "" 128)
     "00000000000000000000000000000010")

    (check-equal? 
     (unpadding-ansix923 "00000000000000000000000000000010" 128)
     "")

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

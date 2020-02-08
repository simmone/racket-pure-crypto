#lang racket

(require rackunit)
(require rackunit/text-ui)

(require file/sha1)

(require "../../../src/cipher/aes/s-box.rkt")

(define test-s-box
  (test-suite
   "test-s-box"
   
   (test-case
    "test-(inv)sub-byte"
    
    (check-equal? (sub-byte "00") "63")
    (check-equal? (inv-sub-byte "63") "00")

    (check-equal? (sub-byte "0") "63")
    (check-equal? (sub-byte 0) "63")

    (check-equal? (inv-sub-byte "0") "52")
    (check-equal? (inv-sub-byte 0) "52")

    (check-equal? (sub-byte "0f") "76")
    (check-equal? (inv-sub-byte "76") "0f")

    (check-equal? (sub-byte "f") "76")
    (check-equal? (sub-byte 15) "76")

    (check-equal? (inv-sub-byte "f") "fb")
    (check-equal? (inv-sub-byte 15) "fb")

    (check-equal? (sub-byte "80") "cd")
    (check-equal? (inv-sub-byte "cd") "80")
    (check-equal? (sub-byte (bytes-ref (hex-string->bytes "80") 0)) "cd")

    (check-equal? (sub-byte "ff") "16")
    (check-equal? (inv-sub-byte "16") "ff")
    (check-equal? (sub-byte (bytes-ref (hex-string->bytes "ff") 0)) "16")

    (check-equal? (sub-byte "87") "17")
    (check-equal? (inv-sub-byte "17") "87")
    (check-equal? (sub-byte (bytes-ref (hex-string->bytes "87") 0)) "17")
    )

   (test-case
    "test-sub-word"
    
    (check-equal? (sub-word "80000fff") "cd637616")
    (check-equal? (inv-sub-word "cd637616") "80000fff")

    (check-equal? (sub-word"cf4f3c09") "8a84eb01")
    (check-equal? (inv-sub-word "8a84eb01") "cf4f3c09") 

    (check-equal? (sub-word "6c76052a") "50386be5")
    (check-equal? (inv-sub-word "50386be5") "6c76052a")

    )

   (test-case
    "test-sub-block"

    (check-equal? (sub-block "00102030405060708090a0b0c0d0e0f0")
                  "63cab7040953d051cd60e0e7ba70e18c")

    (check-equal? (inv-sub-block "63cab7040953d051cd60e0e7ba70e18c")
                   "00102030405060708090a0b0c0d0e0f0")
    )

   ))

(run-tests test-s-box)

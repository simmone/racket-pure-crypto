#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../../src/cipher/aes/aes.rkt")
(require "../../../../../racket-detail/detail/main.rkt")

(define test-aes
  (test-suite
   "test-aes"
   
   (test-case
    "test-aes-128"

    (check-equal? 
     (detail 
      #:formats? '("aes.pdf")
      (lambda ()
        (detail-page
         (lambda ()
           (aes "00112233445566778899aabbccddeeff"
                "000102030405060708090a0b0c0d0e0f")))))
     "69c4e0d86a7b0430d8cdb78070b4c55a")

    (check-equal? 
     (unaes "69c4e0d86a7b0430d8cdb78070b4c55a"
          "000102030405060708090a0b0c0d0e0f")
      "00112233445566778899aabbccddeeff"
      )
    )

   (test-case
    "test-aes-192"

    (check-equal? 
     (aes "00112233445566778899aabbccddeeff"
          "000102030405060708090a0b0c0d0e0f1011121314151617")
     "dda97ca4864cdfe06eaf70a0ec0d7191")

    (check-equal? 
     (unaes "dda97ca4864cdfe06eaf70a0ec0d7191"
            "000102030405060708090a0b0c0d0e0f1011121314151617")
      "00112233445566778899aabbccddeeff")
    )

   (test-case
    "test-aes-256"

    (check-equal? 
     (aes "00112233445566778899aabbccddeeff"
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
     "8ea2b7ca516745bfeafc49904b496089")

    (check-equal? 
     (unaes "8ea2b7ca516745bfeafc49904b496089"
          "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
     "00112233445566778899aabbccddeeff")
    )

   ))

(run-tests test-aes)

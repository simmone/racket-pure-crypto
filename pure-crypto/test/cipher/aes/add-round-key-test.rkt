#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../../src/cipher/aes/add-round-key.rkt")

(define test-add-round-key
  (test-suite
   "test-add-round-key"
   
   (test-case
    "test-add-round-key"
    
    (check-equal?
     (add-round-key
      "3243f6a8885a308d313198a2e0370734"
      "2b7e151628aed2a6abf7158809cf4f3c")
     "193de3bea0f4e22b9ac68d2ae9f84808")

    (check-equal?
     (add-round-key
      "00112233445566778899aabbccddeeff"
      "000102030405060708090a0b0c0d0e0f")
     "00102030405060708090a0b0c0d0e0f0")
    )

   ))

(run-tests test-add-round-key)

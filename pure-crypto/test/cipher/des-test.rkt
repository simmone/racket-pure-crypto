#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../src/cipher/des.rkt")

(define test-des
  (test-suite
   "test-des"

   (test-case
    "test-ecb"

    (check-equal? 
     (des
      "0000000100000000111111101111111100000000000000010000000011111110"
      "0110000100000111000001110000011100000111000001110000011100000111"
      #:detail? '(console "ecb.pdf"))
     "1001001000010110010101001001010111101101101001001000001001001101")
    )

   ))

 (run-tests test-des)

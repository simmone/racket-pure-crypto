#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../../src/cipher/aes/lib.rkt")

(define test-lib
  (test-suite
   "test-lib"

   (test-case
    "test-rot-word"
    
    (check-equal? (rot-word "09cf4f3c" 1) "cf4f3c09")
    (check-equal? (rot-word "2a6c7605" 1) "6c76052a")

    (check-equal? (rot-word "2a6c7605" 2) "76052a6c")
    (check-equal? (rot-word "2a6c7605" 3) "052a6c76")
    (check-equal? (rot-word "2a6c7605" 4) "2a6c7605")
    (check-equal? (rot-word "2a6c7605" 5) "6c76052a")
    )
   
   (test-case
    "test-bitwise-string-shift-left"
    
    (check-equal? (bitwise-string-shift-left "11010100") "10101000")

    (check-equal? (bitwise-string-shift-left "11111111") "11111110")
    )
   
   ))

(run-tests test-lib)

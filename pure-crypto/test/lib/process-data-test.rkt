#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../src/lib/process-data.rkt")
(require "../../../../racket-detail/detail/main.rkt")

(define test-process-data
  (test-suite
   "test-process-data"

   (test-case
    "test-process-data"

    (let ([result
           (detail 
            #:formats? #f
            (lambda ()
              (detail-page
               (lambda ()
                 (process-data "a" 64 16 8)))))])
      (check-equal? (car result) '("6107070707070707"))
      (check-equal? (cdr result) '("0110000100000111000001110000011100000111000001110000011100000111")))

    (let ([result
           (detail 
            #:formats? #f
            (lambda ()
              (detail-page
               (lambda ()
                 (process-data "a" 128 32 16)))))])
      (check-equal? (car result) '("610f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"))
      (check-equal? (cdr result) '("01100001000011110000111100001111000011110000111100001111000011110000111100001111000011110000111100001111000011110000111100001111")))

    )
   ))

 (run-tests test-process-data)

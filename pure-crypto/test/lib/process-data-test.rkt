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
            #:formats '(console "process-data.pdf")
            (lambda ()
              (detail-page
               (lambda ()
                 (process-data "a")))))])
      (check-equal? (car result) '("6107070707070707"))
      (check-equal? (cdr result) '("0110000100000111000001110000011100000111000001110000011100000111")))
    )
   ))

 (run-tests test-process-data)

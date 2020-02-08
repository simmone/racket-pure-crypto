#lang racket

(require rackunit)
(require rackunit/text-ui)

(require file/sha1)

(require "../../../src/cipher/aes/shift-rows.rkt")

(define test-shift-rows
  (test-suite
   "test-shift-rows"
   
   (test-case
    "test-block-row->col"
    
    (check-equal? (block-row->col "63cab7040953d051cd60e0e7ba70e18c")
                  "6309cdbaca536070b7d0e0e10451e78c")

    (check-equal? (block-row->col "6309cdbaca536070b7d0e0e10451e78c")
                   "63cab7040953d051cd60e0e7ba70e18c")
    )
   
   (test-case
    "test-shift-rows"

    (check-equal? (shift-rows "63cab7040953d051cd60e0e7ba70e18c")
                  "6353e08c0960e104cd70b751bacad0e7")
    )

   (test-case
    "test-inv-shift-rows"

    (check-equal? (inv-shift-rows "6353e08c0960e104cd70b751bacad0e7")
                  "63cab7040953d051cd60e0e7ba70e18c")
    )

   ))

(run-tests test-shift-rows)

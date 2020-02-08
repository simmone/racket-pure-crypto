#lang racket

(require rackunit)
(require rackunit/text-ui)

(require "../../../src/cipher/aes/mix-columns.rkt")

(define test-mix-columns
  (test-suite
   "test-(inv)mix-columns"
   
   (test-case
    "test-matrix-multiply"

    (check-equal? (matrix-multiply '(2 3 1 1) "d4bf5d30") "04")
    (check-equal? (matrix-multiply '(1 2 3 1) "d4bf5d30") "66")
    (check-equal? (matrix-multiply '(1 1 2 3) "d4bf5d30") "81")
    (check-equal? (matrix-multiply '(3 1 1 2) "d4bf5d30") "e5")

    (check-equal? (matrix-multiply '(2 3 1 1) "6353e08c") "5f")
    (check-equal? (matrix-multiply '(1 2 3 1) "6353e08c") "72")
    (check-equal? (matrix-multiply '(1 1 2 3) "6353e08c") "64")
    (check-equal? (matrix-multiply '(3 1 1 2) "6353e08c") "15")
    )

   (test-case
    "test-(inv)mix-column"

    (check-equal? (mix-column "d4bf5d30") "046681e5")
    (check-equal? (inv-mix-column "046681e5") "d4bf5d30")
    )
   
   (test-case
    "test-(inv)mix-columns"

    (check-equal? (mix-columns "6353e08c0960e104cd70b751bacad0e7")
                  "5f72641557f5bc92f7be3b291db9f91a")

    (check-equal? (inv-mix-columns "5f72641557f5bc92f7be3b291db9f91a")
                   "6353e08c0960e104cd70b751bacad0e7")

    (check-equal? (mix-columns "6353e08c0960e104cd70b751bacad0e7")
                  "5f72641557f5bc92f7be3b291db9f91a")

    (check-equal? (inv-mix-columns "5f72641557f5bc92f7be3b291db9f91a")
                  "6353e08c0960e104cd70b751bacad0e7")
    )

   ))

(run-tests test-mix-columns)

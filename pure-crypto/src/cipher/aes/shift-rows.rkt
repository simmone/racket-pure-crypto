#lang racket

(require "lib.rkt")

(provide (contract-out
          [block-row->col (->
                          (and/c string? #px"^([0-9]|[a-f]){32}$")
                          (and/c string? #px"^([0-9]|[a-f]){32}$"))]
          [shift-rows (->
                       (and/c string? #px"^([0-9]|[a-f]){32}$")
                       (and/c string? #px"^([0-9]|[a-f]){32}$"))]
          [inv-shift-rows (->
                       (and/c string? #px"^([0-9]|[a-f]){32}$")
                       (and/c string? #px"^([0-9]|[a-f]){32}$"))]
          ))

(define (block-row->col block)
  (string-append
   (substring block 0 2)
   (substring block 8 10)
   (substring block 16 18)
   (substring block 24 26)

   (substring block 2 4)
   (substring block 10 12)
   (substring block 18 20)
   (substring block 26 28)

   (substring block 4 6)
   (substring block 12 14)
   (substring block 20 22)
   (substring block 28 30)

   (substring block 6 8)
   (substring block 14 16)
   (substring block 22 24)
   (substring block 30 32)))

(define (shift-rows block)
  (let ([new_block (block-row->col block)])
    (set! new_block
          (string-append
           (substring new_block 0 8)
           (rot-word (substring new_block 8 16) 1)
           (rot-word (substring new_block 16 24) 2)
           (rot-word (substring new_block 24 32) 3)))
    (block-row->col new_block)))

(define (inv-shift-rows block)
  (let ([new_block (block-row->col block)])
    (set! new_block
          (string-append
           (substring new_block 0 8)
           (rot-word (substring new_block 8 16) 3)
           (rot-word (substring new_block 16 24) 2)
           (rot-word (substring new_block 24 32) 1)))
    (block-row->col new_block)))





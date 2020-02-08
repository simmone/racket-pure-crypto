#lang racket

(require "s-box.rkt")

(provide (contract-out
          [add-round-key (->
                          (and/c string? #px"^([0-9]|[a-f]){32}$")
                          (and/c string? #px"^([0-9]|[a-f]){32}$")
                          (and/c string? #px"^([0-9]|[a-f]){32}$"))]
          ))

(define (add-round-key block key)
  (~r #:base 16 #:min-width 32 #:pad-string "0"
      (bitwise-xor
       (string->number block 16)
       (string->number key 16))))

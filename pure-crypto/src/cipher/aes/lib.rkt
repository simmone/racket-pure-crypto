#lang racket

(provide (contract-out
          [rot-word (-> 
                     (and/c string? #px"^([0-9]|[a-f]){8}$")
                     natural?
                     (and/c string? #px"^([0-9]|[a-f]){8}$"))]
          [bitwise-string-shift-left (-> 
                     (and/c string? #px"^([0-1]){8}$")
                     (and/c string? #px"^([0-1]){8}$"))]
          ))

(define (rot-word w count)
  (let loop ([loop_count 0]
             [result w])
    (if (< loop_count count)
        (loop
         (add1 loop_count)
         (string-append
          (substring result 2 4)
          (substring result 4 6)
          (substring result 6 8)
          (substring result 0 2)))
        result)))

(define (bitwise-string-shift-left bits)
  (string-append (substring bits 1 8) "0"))


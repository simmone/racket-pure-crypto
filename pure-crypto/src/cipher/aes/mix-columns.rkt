#lang racket

(require "lib.rkt")

(provide (contract-out
          [mix-columns (->
                       (and/c string? #px"^([0-9]|[a-f]){32}$")
                       (and/c string? #px"^([0-9]|[a-f]){32}$"))]
          [inv-mix-columns (->
                       (and/c string? #px"^([0-9]|[a-f]){32}$")
                       (and/c string? #px"^([0-9]|[a-f]){32}$"))]
          [mix-column (->
                       (and/c string? #px"^([0-9]|[a-f]){8}$")
                       (and/c string? #px"^([0-9]|[a-f]){8}$"))]
          [inv-mix-column (->
                       (and/c string? #px"^([0-9]|[a-f]){8}$")
                       (and/c string? #px"^([0-9]|[a-f]){8}$"))]
          [matrix-multiply (->
                            (list/c natural? natural? natural? natural?)
                            (and/c string? #px"^([0-9]|[a-f]){8}$")
                            (and/c string? #px"^([0-9]|[a-f]){2}$"))]
          ))

(define (mix-columns block)
  (string-append
   (mix-column (substring block 0 8))
   (mix-column (substring block 8 16))
   (mix-column (substring block 16 24))
   (mix-column (substring block 24 32))))

(define (inv-mix-columns block)
  (string-append
   (inv-mix-column (substring block 0 8))
   (inv-mix-column (substring block 8 16))
   (inv-mix-column (substring block 16 24))
   (inv-mix-column (substring block 24 32))))

(define (mix-column word)
  (string-append
    (matrix-multiply '(2 3 1 1) word)
    (matrix-multiply '(1 2 3 1) word)
    (matrix-multiply '(1 1 2 3) word)
    (matrix-multiply '(3 1 1 2) word)))

(define (inv-mix-column word)
  (string-append
    (matrix-multiply '(14 11 13 9) word)
    (matrix-multiply '(9 14 11 13) word)
    (matrix-multiply '(13 9 14 11) word)
    (matrix-multiply '(11 13 9 14) word)))

(define (x2 col_val)
  (let* ([c_bits (~r #:base 2 #:min-width 8 #:pad-string "0" col_val)]
         [c_bits_shift (bitwise-string-shift-left c_bits)])
    (if (char=? (string-ref c_bits 0) #\1)
        (bitwise-xor (string->number c_bits_shift 2) (string->number "00011011" 2))
        (string->number c_bits_shift 2))))

(define (+x val col_val)
  (bitwise-xor val col_val))

(define (matrix-multiply matrix col)
  (~r #:base 16 #:min-width 2 #:pad-string "0"
      (let loop ([loop_matrix matrix]
                 [loop_col (list
                            (substring col 0 2)
                            (substring col 2 4)
                            (substring col 4 6)
                            (substring col 6 8))]
                 [last_result 0])
        (if (not (null? loop_matrix))
            (let* ([m (car loop_matrix)]
                   [col_val (string->number (car loop_col) 16)])
              (loop
               (cdr loop_matrix)
               (cdr loop_col)
               (bitwise-xor
                last_result
                (cond
                 [(= m 2)
                  (x2 col_val)]
                 [(= m 3)
                  (+x (x2 col_val) col_val)]
                 [(= m 9)
                  (+x (x2 (x2 (x2 col_val))) col_val)]
                 [(= m 11)
                  (+x (x2 (+x (x2 (x2 col_val)) col_val)) col_val)]
                 [(= m 13)
                  (+x (x2 (x2 (+x (x2 col_val) col_val))) col_val)]
                 [(= m 14)
                  (x2 (+x (x2 (+x (x2 col_val) col_val)) col_val))]
                 [(= m 1)
                  col_val]))))
            last_result))))



#lang racket

(require "s-box.rkt")
(require "shift-rows.rkt")
(require "key-expansion.rkt")
(require "add-round-key.rkt")
(require "mix-columns.rkt")

(provide (contract-out
          [aes (->
                (and/c string? #px"^([0-9]|[a-f]){32}$")
                (and/c string?
                       (or/c #px"^([0-9]|[a-f]){32}$" #px"^([0-9]|[a-f]){48}$" #px"^([0-9]|[a-f]){64}$"))
                (and/c string? #px"^([0-9]|[a-f]){32}$"))]
          [unaes (->
                  (and/c string? #px"^([0-9]|[a-f]){32}$")
                  (and/c string?
                         (or/c #px"^([0-9]|[a-f]){32}$" #px"^([0-9]|[a-f]){48}$" #px"^([0-9]|[a-f]){64}$"))
                  (and/c string? #px"^([0-9]|[a-f]){32}$"))]
          ))

(define (aes block key)
  (let ([nb 4]
        [nk #f]
        [nr #f]
        [key_size (string-length key)])

    (cond
     [(= key_size 32)
      (set! nk 4)
      (set! nr 10)]
     [(= key_size 48)
      (set! nk 6)
      (set! nr 12)]
     [(= key_size 64)
      (set! nk 8)
      (set! nr 14)])
    
    (let ([w (key-expansion key nk nr)]
          [state block])

      (set! state (add-round-key state (list-ref w 0)))
      
      (let loop ([round 1])
        (when (<= round (sub1 nr))
          (set! state (sub-block state))

          (set! state (shift-rows state))

          (set! state (mix-columns state))

          (set! state (add-round-key state (list-ref w round)))

          (loop (add1 round))))

      (set! state (sub-block state))

      (set! state (shift-rows state))

      (set! state (add-round-key state (list-ref w nr)))

      state)))

(define (unaes block key)
  (let ([nb 4]
        [nk #f]
        [nr #f]
        [key_size (string-length key)])

    (cond
     [(= key_size 32)
      (set! nk 4)
      (set! nr 10)]
     [(= key_size 48)
      (set! nk 6)
      (set! nr 12)]
     [(= key_size 64)
      (set! nk 8)
      (set! nr 14)])

    (let ([w (key-expansion key nk nr)]
          [state block])

      (set! state (add-round-key state (list-ref w nr)))

      (let loop ([round 1])
        (when (<= round (sub1 nr))
          (set! state (inv-shift-rows state))

          (set! state (inv-sub-block state))

          (set! state (add-round-key state (list-ref w (- nr round))))

          (set! state (inv-mix-columns state))

          (loop (add1 round))))

      (set! state (inv-shift-rows state))

      (set! state (inv-sub-block state))

      (set! state (add-round-key state (list-ref w 0)))

      state)))

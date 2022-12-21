#lang racket

(require "lib.rkt")
(require "s-box.rkt")

(provide (contract-out
          [rcon (-> natural?
                    (and/c string? #px"^([0-9]|[a-f]){2}$"))]
          [key-expansion (->
                          (or/c
                           (and/c string? #px"^([0-9]|[a-f]){32}$")
                           (and/c string? #px"^([0-9]|[a-f]){48}$")
                           (and/c string? #px"^([0-9]|[a-f]){64}$"))
                          natural? natural? (or/c void? (listof string?)))]
          ))

;; Galios Field "x8+x4+x3+x+1" = 283(11b in hex)
(define (rcon round)
  (~r #:min-width 2 #:base 16 #:pad-string "0"
      (cond
       [(= round 1)
        1]
       [else
        (let* ([val_1 (string->number (rcon (sub1 round)) 16)])
          (if (< val_1 128)
              (* val_1 2)
              (bitwise-xor
               (* val_1 2)
               283)))])))

(define (key-expansion key_hex_str nk nr)
  (let ([w_hash (make-hash)]
        [result_list #f])

    (set! result_list
          (let loop ([loop_key key_hex_str]
                     [i 0]
                     [loop_list '()])
            (if (< i nk)
                (let ([key (substring loop_key 0 8)])
                  (hash-set! w_hash i key)
                  (loop
                   (substring loop_key 8)
                   (add1 i)
                   (cons key loop_list)))
                loop_list)))

       (set! result_list
             (let loop ([i nk]
                        [loop_list result_list])
               (if (< i (* 4 (add1 nr)))
                   (let* ([temp_hex (hash-ref w_hash (sub1 i))]
                          [temp_val (string->number temp_hex 16)]
                          [result #f])

                        (if (= (modulo i nk) 0)
                            (let ([sub_rot_i (sub-word (rot-word temp_hex 1))]
                                  [rcon_i (string-append (rcon (quotient i nk)) "000000")])
                              (set! temp_val
                                    (bitwise-xor (string->number sub_rot_i 16) (string->number rcon_i 16))))
                            (when (and (> nk 6) (= (modulo i nk) 4))
                              (set! temp_val (string->number (sub-word temp_hex) 16))))
                        
                        (let* ([i_nk (- i nk)]
                               [wi_nk (hash-ref w_hash i_nk)])
                          
                          (set! result
                                (~r #:base 16 #:min-width 8 #:pad-string "0"
                                    (bitwise-xor
                                     (string->number wi_nk 16) temp_val)))

                          (hash-set! w_hash i result))

                        (loop (add1 i) (cons result loop_list)))
                   (reverse loop_list))))

    (let ([block_list
           (let loop ([loop_list result_list]
                      [r_list '()])
             (if (not (null? loop_list))
                 (loop
                  (list-tail loop_list 4)
                  (cons
                   (string-append (first loop_list) (second loop_list) (third loop_list) (fourth loop_list))
                   r_list))
                 (reverse r_list)))])
      block_list)))

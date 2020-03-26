#lang racket

(require "lib.rkt")
(require "s-box.rkt")

(require detail)

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
  (detail-h2 "Key Expansion")

  (detail-list
   (lambda ()
     (detail-row (lambda ()
                   (detail-col "key_hex_str: ")
                   (detail-col key_hex_str #:width? 40)))
     (detail-row (lambda ()
                   (detail-col "nk: ")
                   (detail-col (number->string nk))))
     (detail-row (lambda ()
                   (detail-col "nr: ")
                   (detail-col (number->string nr))))))

  (detail-line "--------")

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

    (detail-simple-list (reverse result_list) #:font_size? 'small #:cols_count? nk)

    (detail-line "--------")

    (detail-list
     #:font_size? 'small
     (lambda ()
       (set! result_list
             (let loop ([i nk]
                        [loop_list result_list])
               (if (< i (* 4 (add1 nr)))
                   (let* ([temp_hex (hash-ref w_hash (sub1 i))]
                          [temp_val (string->number temp_hex 16)]
                          [result #f])

                     (detail-row
                      (lambda ()
                        (detail-col (string-append (number->string i) ": "))
                        (detail-col (format "temp[~a] " temp_hex))

                        (if (= (modulo i nk) 0)
                            (let ([sub_rot_i (sub-word (rot-word temp_hex 1))]
                                  [rcon_i (string-append (rcon (quotient i nk)) "000000")])
                              (detail-col (format "sub_rot_i[~a] " sub_rot_i))
                              (detail-col (format "rcon_i[~a] " rcon_i))
                              (set! temp_val
                                    (bitwise-xor (string->number sub_rot_i 16) (string->number rcon_i 16))))
                            (when (and (> nk 6) (= (modulo i nk) 4))
                              (set! temp_val (string->number (sub-word temp_hex) 16))))))

                     (detail-row
                      (lambda ()
                        (detail-col "")
                        (detail-col (format "val[~a] " (~r #:base 16 #:min-width 8 temp_val)))

                        (let* ([i_nk (- i nk)]
                               [wi_nk (hash-ref w_hash i_nk)])
                          
                          (set! result
                                (~r #:base 16 #:min-width 8 #:pad-string "0"
                                    (bitwise-xor
                                     (string->number wi_nk 16) temp_val)))

                          (detail-col (format "w[~a]:[~a] " i_nk wi_nk))
                          (detail-col (format "result:[~a]" result))

                          (hash-set! w_hash i result))))

                     (loop (add1 i) (cons result loop_list)))
                   (reverse loop_list))))))

    (detail-line "--------")
    
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

      (detail-simple-list block_list #:cols_count? 1)
      
      block_list)))

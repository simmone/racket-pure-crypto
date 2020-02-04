#lang racket

(require file/sha1)
(require net/base64)

(require "../../../../racket-detail/detail/main.rkt")

(require "constants.rkt")
(require "lib.rkt")
(require "padding.rkt")

(provide (contract-out
          [process-key (->*
                         (string?)
                         (
                          #:iv? (and/c string? #px"^([0-9]|[a-f]){16}$")
                          #:key_format? (or/c 'hex 'base64 'utf-8)
                         )
                         (cons/c (listof (listof string?)) string?))]
          ))

(define (process-key
         key
         #:iv? [iv? "0000000000000000"]
         #:key_format? [key_format? 'utf-8])
  (detail-div
   #:font_size 'small
   #:line_break_length 100
   (lambda ()
     (detail-h2 "Prepare Key")

     (detail-line (format "key:[~a][~a]" key key_format?))
     
     (define hex_key
       (string-upcase
        (cond
         [(eq? key_format? 'utf-8)
          (bytes->hex-string (string->bytes/utf-8 key))]
         [(eq? key_format? 'base64)
          (bytes->hex-string (base64-decode (string->bytes/utf-8 key)))]
         [else
          key])))

     (detail-line (format "key in hex:[~a]" hex_key))

     (when (and
            (not (= (string-length hex_key) 16))
            (not (= (string-length hex_key) 32))
            (not (= (string-length hex_key) 48)))
       (error (format "key length is invalid. expect 16/32/48(hex), but get ~a" (string-length hex_key))))
  
     (define hex_keys
       (cond
        [(= (string-length hex_key) 16)
         (list (substring hex_key 0 16))]
        [(= (string-length hex_key) 32)
         (list
          (substring hex_key 0 16)
          (substring hex_key 16 32)
          (substring hex_key 0 16))]
        [(= (string-length hex_key) 48)
         (list
          (substring hex_key 0 16)
          (substring hex_key 16 32)
          (substring hex_key 32 48))]))

     (detail-line "to keys:")
     (detail-simple-list hex_keys #:cols_count 4)

     (detail-line (format "iv:[~a]" iv?))
     (define iv_bin (~r #:min-width 64 #:base 2 #:pad-string "0" (string->number iv? 16)))
     (detail-line (format "iv in binary:[~a]" iv_bin))

     (define k_list
       (let loop-keys ([loop_keys hex_keys]
                       [loop_k_lists '()])
         (if (not (null? loop_keys))
             (let ([key_b8_list #f]
                   [key_56b #f]
                   [key_56b_list #f]
                   [c0 #f]
                   [d0 #f]
                   [c_list #f]
                   [d_list #f]
                   [loop_k_list #f])

               (detail-line (format "key:[~a]" (car loop_keys)))
               (set! key_b8_list (hex-string->binary-string-list (car loop_keys) 8))
               (detail-line "key_b8_list:")
               (detail-simple-list key_b8_list #:cols_count 4)

               (detail-line "key_56b_list:")
               (set! key_56b
                     (transform-binary-string
                      (hex-string->binary-string (car loop_keys))
                      *pc1_table*))
               
               (set! key_56b_list (split-string key_56b 7))
               (detail-simple-list key_56b_list #:cols_count 4)

               (set! c0 (substring key_56b 0 28))
               (set! d0 (substring key_56b 28))

               (detail-line "c_list:")
               (set! c_list
                     (let loop ([shifts *shift_length_list*]
                                [loop_c c0]
                                [result_list '()])
                       (if (not (null? shifts))
                           (let ([next_c (shift-left loop_c (car shifts))])
                             (loop
                              (cdr shifts)
                              next_c
                              (cons next_c result_list)))
                           (reverse result_list))))
               (detail-simple-list c_list #:cols_count 1)

               (detail-line "d_list:")
               (set! d_list
                     (let loop ([shifts *shift_length_list*]
                                [loop_d d0]
                                [result_list '()])
                       (if (not (null? shifts))
                           (let ([next_d (shift-left loop_d (car shifts))])
                             (loop
                              (cdr shifts)
                              next_d
                              (cons next_d result_list)))
                           (reverse result_list))))
               (detail-simple-list d_list #:cols_count 1)
               
               (detail-line "loop_k_list:")
               (set! loop_k_list
                     (let loop ([loop_c_list c_list]
                                [loop_d_list d_list]
                                [result_list '()])
                       (if (not (null? loop_c_list))
                           (loop
                            (cdr loop_c_list)
                            (cdr loop_d_list)
                            (cons
                             (transform-binary-string
                              (string-append (car loop_c_list) (car loop_d_list))
                              *pc2_table*)
                             result_list))
                           (reverse result_list))))
               (detail-simple-list
                (map
                 (lambda (k)
                   (foldr (lambda (a b) (string-append a " " b)) "" (split-string k 6)))
                 loop_k_list)
                #:cols_count 1)
               
               (loop-keys (cdr loop_keys) (cons loop_k_list loop_k_lists)))
             (reverse loop_k_lists))))

     (cons k_list iv_bin))))

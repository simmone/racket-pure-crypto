#lang racket

(require file/sha1)
(require net/base64)

(provide (contract-out
          [undes (->
                (and/c string? #px"^([0-1]){64}$")
                (listof (and/c string? #px"^([0-1]){48}$"))
                (and/c string? #px"^([0-1]){64}$"))
               ]
          ))

(require "../../../../racket-detail/detail/main.rkt")
(require "../lib/constants.rkt")
(require "../lib/lib.rkt")

(define (undes binary_data k_list)
  (let ([ip1 #f]
        [l16 #f]
        [r16 #f])
    (detail-div
     #:line_break_length 64
     #:font_size 'small
     (lambda ()
       
       (detail-h3 "UNDES BLOCK DETAIL")

       (detail-line "encrytped_binary_data:")
       (detail-line binary_data)
                    
       (detail-line "ip1:")
       (set! ip1 (transform-binary-string binary_data *reverse_ip_1_table*))
       (detail-line ip1)
     
       (detail-line "l16:")
       (set! l16 (substring ip1 32))
       (detail-line l16)

       (detail-line "r16:")
       (set! r16 (substring ip1 0 32))
       (detail-line r16)

       (let loop ([rn_1 l16]
                  [rn r16]
                  [n 16])
         (if (>= n 1)
             (let* ([en #f]
                    [kn #f]
                    [kn_xor_en #f]
                    [sbn #f]
                    [fn #f]
                    [ln_1 #f])

               (detail-line (format "--------n: ~a--------" n))

               (detail-line "transform rn_1:")
               (set! en (transform-binary-string rn_1 *e_table*))
               (detail-line en #:line_break_length 64)

               (detail-line (format "k~a:" n))
               (set! kn (list-ref k_list (sub1 n)))
               (detail-simple-list (split-string kn 6) #:cols_count 8)

               (detail-line (format "k~a xor e~a:" n n))
               (set! kn_xor_en
                     (~r #:base 2 #:min-width 48 #:pad-string "0"
                         (bitwise-xor (string->number kn 2) (string->number en 2))))
               (detail-simple-list (split-string kn_xor_en 6) #:cols_count 8)

               (detail-line (format "sb~a:" n))
               (set! sbn
                     (let loop-sb ([loop_list (split-string kn_xor_en 6)]
                                   [index 1]
                                   [result_str ""])
                       (if (not (null? loop_list))
                           (loop-sb (cdr loop_list) (add1 index) (string-append result_str (b6->b4 index (car loop_list))))
                           result_str)))
               (detail-simple-list (split-string sbn 4) #:cols_count 8)

               (detail-line (format "f~a(sb~a transformed by p_table):" n n))
               (set! fn (transform-binary-string sbn *p_table*))
               (detail-simple-list (split-string fn 4) #:cols_count 8)

               (detail-line "transform ln_1:")
               (set! ln_1
                     (~r #:base 2 #:min-width 32 #:pad-string "0"
                         (bitwise-xor (string->number rn 2) (string->number fn 2))))
               (detail-line ln_1)

               (loop
                ln_1
                rn_1
                (sub1 n)))
        (let ([l0r0 #f]
              [binary_data #f])
          (detail-line "l0r0:")
          (set! l0r0 (string-append rn_1 rn))
          (detail-line l0r0)
          
          (detail-line "binary_data:")
          (set! binary_data (transform-binary-string l0r0 *reverse_ip_table*))
          (detail-line binary_data)

          binary_data)))))))

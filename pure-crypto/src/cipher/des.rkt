#lang racket

(require file/sha1)
(require net/base64)

(provide (contract-out
          [des (->* (
                     natural?
                     (and/c string? #px"^([0-1]){64}$")
                     (and/c string? #px"^([0-1]){64}$")
                     )
                    (#:detail? (or/c #f (listof (or/c 'raw 'console path-string?))))
                    (and/c string? #px"^([0-1]){64}$"))
               ]
          ))

(require "../../../../racket-detail/detail/main.rkt")
(require "../lib/lib.rkt")

(define (des 
         block_index key operated_binary_data
         #:detail? [detail? #f])
  (let* ([m0 operated_binary_data]
         [ip0 (transform-binary-string m0 *ip_table*)]
         [l0 (substring ip0 0 32)]
         [r0 (substring ip0 32)]
         [encrypted_block_binary_data #f])

    (detail-page
     (lambda ()

       (detail-h1 "DES Encryption")

       (detail-list
        (lambda ()
          (detail-row (lambda () (detail-col "block index:") (detail-col (number->string block_index))))
          (detail-row (lambda () (detail-col "m0:") (detail-col m0)))
          (detail-row (lambda () (detail-col "ip0:") (detail-col ip0)))
          (detail-row (lambda () (detail-col "l0:") (detail-col l0)))
          (detail-row (lambda () (detail-col "r0:") (detail-col r0)))))

       (let loop-encode ([ln_1 l0]
                         [rn_1 r0]
                         [n 1])
         (if (<= n 16)
             (let* ([en (transform-binary-string rn_1 *e_table*)]
                    [kn key]
                    [kn_xor_en
                     (~r #:base 2 #:min-width 48 #:pad-string "0"
                         (bitwise-xor (string->number kn 2) (string->number en 2)))]
                    [sbn
                     (let loop-sb ([loop_list (split-string kn_xor_en 6)]
                                   [index 1]
                                   [result_str ""])
                       (if (not (null? loop_list))
                           (loop-sb (cdr loop_list) (add1 index) (string-append result_str (b6->b4 index (car loop_list))))
                           result_str))]
                    [fn (transform-binary-string sbn *p_table*)]
                    [rn
                     (~r #:base 2 #:min-width 32 #:pad-string "0"
                         (bitwise-xor (string->number ln_1 2) (string->number fn 2)))])

             (detail-line (format "--------[~a]n: ~a--------" block_index n))
             (detail-line (format "l~a:") (sub1 n))
             (detail-simple-list (split-string ln_1 4) #:cols_count 8)
             (detail-line (format "r~a:") (sub1 n))
             (detail-simple-list (split-string rn_1 4) #:cols_count 8)
             (detail-line (format "e~a(r~a transformed by e_table)" n (sub1 n)))
             (detail-simple-list (split-string en 6) #:cols_count 8)
             (detail-line (format "k~a:" n))
             (detail-simple-list (split-string kn 6) #:cols_count 8)
             (detail-line (format "k~a xor e~a:" n n))
             (detail-simple-list (split-string kn_xor_en 6) #:cols_count 8)
             (detail-line (format "sb~a:" n))
             (detail-simple-list (split-string sbn 4) #:cols_count 8)
             (detail-line (format "f~a(sb~a transformed by b_table):" n n))
             (detail-simple-list (split-string fn 4) #:cols_count 8)
             (detail-line (format "r~a(l~a xor f~a):" n (sub1 n) n))
             (detail-simple-list (split-string rn 4) #:cols_count 8)
             (detail-line (format "--------[~a]n: ~a--------" block_index n))

             (loop-encode rn_1 rn (add1 n)))
            (let* ([r16l16 (string-append rn_1 ln_1)]
                   [ip1 (transform-binary-string r16l16 *ip_1_table*)])
              (detail-line (format "final[~a]" block_index))
              (detail-line "r16l16:")
              (detail-simple-list (split-string r16l16 8) #:cols_count 8)
              (detail-line "ip1")
              (detail-simple-list (split-string ip1 8) #:cols_count 8)
              (detail-h2 "final hex: {~a}" (string-upcase (~r #:min-width 16 #:base 16 #:pad-string "0" (string->number ip1 2))))
              ip1)))))))

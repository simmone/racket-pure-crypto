#lang racket

(require file/sha1)
(require net/base64)

(provide (contract-out
          [encryption (-> natural? (listof string?) string? boolean? path-string? string?)]
          ))

(require "../../../../racket-detail/detail/main.rkt")

(require "lib/constants.rkt")
(require "lib/lib.rkt")
(require "lib/padding.rkt")

(define (des block_index key operated_binary_data)
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
                    [kn key)]
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
                    (bitwise-xor (string->number ln_1 2) (string->number fn 2)))]
               )

             (detail-line (format "n~a:") n)
             (detail-line (format "l~a:") (sub1 n))
             (detail-simple-list (split-string ln_1 4) #:cols_count 8)
             (detail-line (format "r~a:") (sub1 n))
             (detail-simple-list (split-string rn_1 4) #:cols_count 8)
             (detail-line (format "e~a(r~a transformed by e_table)" n (sub1 n)))
        (printf (display-list (split-string en 6) 7 8))
        (printf "k~a:\n" n)
        (printf (display-list (split-string kn 6) 7 8))
        (printf "k~a xor e~a:\n" n n)
        (printf (display-list (split-string kn_xor_en 6) 7 8))
        (printf "sb~a:\n" n)
        (printf (display-list (split-string sbn 4) 5 8))
        (printf "f~a(sb~a transformed by b_table):\n" n n)
        (printf (display-list (split-string fn 4) 5 8))
        (printf "r~a(l~a xor f~a):\n" n (sub1 n) n)
        (printf (display-list (split-string rn 4) 5 8))
        (printf "--------[~a]n: ~a--------\n\n" block_index n)

             (express express? (lambda () (write-report-des-step block_index n ln_1 rn_1 en kn kn_xor_en sbn fn rn express_path?)))
             (loop-encode rn_1 rn (add1 n)))
            (let* ([r16l16 (string-append rn_1 ln_1)]
                   [ip1 (transform-binary-string r16l16 *ip_1_table*)])
              (express express? (lambda () (write-report-des-final block_index r16l16 ip1 express_path?)))
              ip1))))))))

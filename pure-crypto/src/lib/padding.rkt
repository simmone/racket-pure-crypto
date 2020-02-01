#lang racket

(require "lib.rkt")

(provide (contract-out
          [padding-pkcs5 (-> string? natural? string?)]
          [unpadding-pkcs5 (-> string? natural? string?)]
          [padding-zero (-> string? natural? string?)]
          [unpadding-zero (-> string? natural? string?)]
          [padding-ansix923 (-> string? natural? string?)]
          [unpadding-ansix923 (-> string? natural? string?)]
          [padding-iso10126 (-> string? natural? string?)]
          [unpadding-iso10126 (-> string? natural? string?)]
          ))

(define (repeat-number num)
  (let loop ([counts num]
             [result_str ""])
    (if (not (= counts 0))
        (loop (sub1 counts) (string-append result_str "0" (number->string num)))
        result_str)))

(define (padding-pkcs5 hex64_str group_size)
  (if (< (string-length hex64_str) (/ group_size 4))
      (let ([need_padding_count (floor (/ (- (/ group_size 4)  (string-length hex64_str)) 2))])
        (string-append
         hex64_str
         (repeat-number need_padding_count)))
      hex64_str))

(define (unpadding-pkcs5 hex_str group_size)
  (let ([hex_list (split-string hex_str 2)])
    (let ([padding_number (string->number (last hex_list) 16)])
      (if (<= padding_number 8)
          (let ([expect_padding_string (repeat-number padding_number)])
            (if (regexp-match (regexp (string-append expect_padding_string "$")) hex_str)
                (substring hex_str 0 (- (string-length hex_str) (* padding_number 2)))
                hex_str))
          hex_str))))

(define (padding-zero hex64_str group_size)
  (~a #:min-width (/ group_size 4) #:right-pad-string "0" hex64_str))

(define (unpadding-zero hex_str group_size)
  (string-trim hex_str "0" #:repeat? #t #:left? #f))

(define (padding-ansix923 hex64_str group_size)
  (let ([byte_size (/ group_size 8)])
    (if (< (/ (string-length hex64_str) 2) byte_size)
        (let ([counter_str (~r #:base 16 #:pad-string "0" #:min-width 2 (- byte_size (/ (string-length hex64_str) 2)))])
          (string-append
           (substring 
            (~a #:min-width (* byte_size 2) #:right-pad-string "0" hex64_str)
            0 (- (* byte_size 2) 2))
           counter_str))
        hex64_str)))

(define (unpadding-ansix923 hex_str group_size)
  (let* ([group4_size (/ group_size 4)]
         [counter_str (substring hex_str (- group4_size 2))]
         [counter (string->number counter_str 16)])
    (if (< counter group4_size)
        (let* ([mode_str
                (string-append
                 (repeat-string "00" (sub1 counter))
                 counter_str
                 "$")]
               [split_tries (regexp-split (regexp mode_str) hex_str)])
          (if (= (length split_tries) 2)
              (first split_tries)
              hex_str))
        hex_str)))

(define (padding-iso10126 hex64_str group_size)
  (let ([byte_size (/ group_size 8)])
    (if (< (/ (string-length hex64_str) 2) byte_size)
        (let ([counter (- byte_size (/ (string-length hex64_str) 2))])
          (string-append
           hex64_str
           (with-output-to-string
             (lambda ()
               (let loop ([fill_counts (sub1 counter)])
                 (when (> fill_counts 0)
                       (printf "~a" (string-upcase (number->string (random 16) 16)))
                       (printf "~a" (string-upcase (number->string (random 16) 16)))
                       (loop (sub1 fill_counts))))))
           (~r #:min-width 2 #:base 16 #:pad-string "0" counter)))
        hex64_str)))

(define (unpadding-iso10126 hex_str group_size)
  (let* ([group4_size (/ group_size 4)]
         [counter_str (substring hex_str (- group4_size 2))]
         [counter (string->number counter_str 16)])
    (if (<= counter (/ group4_size 2))
        (substring hex_str 0 (- group4_size (* counter 2)))
        hex_str)))


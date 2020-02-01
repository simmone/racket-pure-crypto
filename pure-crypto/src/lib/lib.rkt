#lang racket

(require file/sha1)

(require "constants.rkt")

(provide (contract-out
          [hex-string->binary-string-list (-> string? (or/c 4 8) list?)]
          [hex-string->binary-string (-> string? string?)]
          [transform-binary-string (-> string? (listof natural?) string?)]
          [reverse-table (-> (listof natural?) (listof natural?))]
          [split-string (-> string? natural? list?)]
          [repeat-string (-> string? natural? string?)]
          [shift-left (-> string? natural? string?)]
          [b6->b4 (-> (or/c 1 2 3 4 5 6 7 8) string? string?)]
          ))

(define (hex-string->binary-string-list hex_str bit_width)
  (let loop ([loop_bytes (string->list hex_str)]
             [result_list '()])
    (if (not (null? loop_bytes))
        (if (= bit_width 4)
            (loop (cdr loop_bytes)
                  (cons 
                   (~r #:base 2 #:min-width 4 #:pad-string "0" (string->number (string (car loop_bytes)) 16))
                   result_list))
            (loop (cddr loop_bytes)
                  (cons
                   (string-append
                    (~r #:base 2 #:min-width 4 #:pad-string "0" (string->number (string (car loop_bytes)) 16))
                    (~r #:base 2 #:min-width 4 #:pad-string "0" (string->number (string (cadr loop_bytes)) 16)))
                   result_list)))
        (reverse result_list))))

(define (hex-string->binary-string hex_str)
  (foldr
   (lambda (a b)
     (string-append a b))
   ""
   (hex-string->binary-string-list hex_str 4)))

(define (reverse-table table)
  (map
   (lambda (item)
     (cdr item))
   (let loop ([vals table]
              [index 1]
              [result_list '()])
     (if (not (null? vals))
         (loop
          (cdr vals)
          (add1 index)
          (cons
           (cons (car vals) index)
           result_list))
         (sort (remove-duplicates result_list #:key car) < #:key car)))))

(define (transform-binary-string bstr btable)
  (list->string
   (map
    (lambda (place)
      (string-ref bstr (sub1 place)))
    btable)))

(define (split-string bit_str width)
  (let loop ([loop_list (string->list bit_str)]
             [unit_list '()]
             [result_list '()])
    (if (not (null? loop_list))
        (if (= (length unit_list) width)
            (loop (cdr loop_list) (list (car loop_list)) (cons (reverse unit_list) result_list))
            (loop (cdr loop_list) (cons (car loop_list) unit_list) result_list))
        (map
         (lambda (unit)
           (list->string unit))
         (if (null? unit_list)
             (reverse result_list)
             (reverse 
              (cons (reverse unit_list) result_list)))))))

(define (shift-left bit_str num)
  (string-append
   (substring bit_str num)
   (substring bit_str 0 num)))

(define (b6->b4 s_index data)
  (~r
   #:base 2
   #:min-width 4
   #:pad-string "0"
   (list-ref
    (list-ref
     (list-ref
      *s_table*
      (sub1 s_index))
     (string->number (string-append (substring data 0 1) (substring data 5 6)) 2))
    (string->number (substring data 1 5) 2))))

(define (repeat-string str count)
  (with-output-to-string
    (lambda ()
      (let loop ([loop_count count])
        (when (> loop_count 0)
              (printf "~a" str)
              (loop (sub1 loop_count)))))))

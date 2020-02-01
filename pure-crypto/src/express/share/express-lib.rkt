#lang racket

(provide (contract-out
          [format-string (-> string? natural? string?)]
          [display-list (->* (list?) (natural? natural?) string?)]
          [display-double-list (->* (list? list?) (natural? natural?) string?)]
          ))

(define (format-string data line_count)
  (with-output-to-string
    (lambda ()
      (let loop ([loop_str data]
                 [result_str ""])
        (if (> (string-length loop_str) line_count)
            (loop (substring loop_str line_count) (printf "~a\n" (substring loop_str 0 line_count)))
            (printf "~a\n" loop_str))))))

(define (display-list input_list [col_width 12] [line_count 10])
  (with-output-to-string
    (lambda ()
      (printf "@verbatim{\n")
      (let loop ([loop_list input_list]
                 [print_count 0]
                 [item_number 1]
                 [line_start? #t]
                 [origin? #t])
        (when (not (null? loop_list))
              (when line_start?
                    (printf (~a #:min-width 6 #:align 'left #:right-pad-string " " (number->string item_number))))

              (if (or (= print_count (sub1 line_count)) (= (length loop_list) 1))
                  (begin
                    (printf (~a #:min-width col_width #:align 'left #:right-pad-string " " (format "~a" (car loop_list))))
                    (printf "\n")
                    (loop (cdr loop_list) 0 (add1 item_number) #t #f))
                  (begin
                    (printf (~a #:min-width col_width #:align 'left #:right-pad-string " " (format "~a" (car loop_list))))
                    (loop (cdr loop_list) (add1 print_count) (add1 item_number) #f #t)))))
      (printf "}"))))


(define (display-double-list input_list result_list [col_width 12] [line_count 10])
  (if (and
       (not (null? input_list))
       (= (length input_list) (length result_list)))
      (with-output-to-string
        (lambda ()
          (printf "@verbatim{\n")
          (let loop ([loop_list result_list]
                     [origin_list input_list]
                     [print_count 0]
                     [item_number 1]
                     [line_start? #t]
                     [origin? #t])
            (when (not (null? loop_list))
                  (if origin?
                      (begin
                        (when line_start?
                              (printf (~a #:min-width 6 #:align 'left #:right-pad-string " ")))
                        
                        (if (or (= print_count (sub1 line_count)) (= (length origin_list) 1))
                            (begin
                              (printf (~a #:min-width col_width #:align 'left #:right-pad-string " " (format "~a" (car origin_list))))
                              (printf "\n")
                              (loop loop_list (cdr origin_list) 0 item_number #t #f))
                            (begin
                              (printf (~a #:min-width col_width #:align 'left #:right-pad-string " " (format "~a" (car origin_list))))
                              (loop loop_list (cdr origin_list) (add1 print_count) item_number #f #t))))
                      (begin
                        (when line_start?
                              (printf (~a #:min-width 6 #:align 'left #:right-pad-string " " (number->string item_number))))
                        
                        (if (or (= print_count (sub1 line_count)) (= (length loop_list) 1))
                            (begin
                              (printf (~a #:min-width col_width #:align 'left #:right-pad-string " " (format "~a" (car loop_list))))
                              (printf "\n")
                              (loop (cdr loop_list) origin_list 0 (add1 item_number) #t #t))
                            (begin
                              (printf (~a #:min-width col_width #:align 'left #:right-pad-string " " (format "~a" (car loop_list))))
                              (loop (cdr loop_list) origin_list (add1 print_count) (add1 item_number) #f #f)))))))
          (printf "}")))
      ""))


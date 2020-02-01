#lang racket

(require "express-lib.rkt")
(require "../../lib/lib.rkt")

(provide (contract-out
          [write-report-k1-k16 (-> string? (listof natural?) (listof string?) path-string? void?)]
          ))

(define (write-report-k1-k16 key pc2_table k_list express_path)
  (let* ([scrbl_dir (build-path express_path "k1-k16")]
         [file_name (format "k1-k16-~a.scrbl" key)]
         [scrbl_file (build-path scrbl_dir file_name)])

    (with-output-to-file
        (build-path express_path "report.scrbl") #:exists 'append
        (lambda ()
          (printf "@include-section[\"k1-k16/~a\"]\n\n" file_name)))

    (make-directory* scrbl_dir)

    (with-output-to-file
        scrbl_file
      (lambda ()
        (printf "#lang scribble/base\n\n")
        (printf "@title{Transform CnDn to Kn[~a]}\n\n" key)
        (printf "@section{PC2 Table[~a]}\n" key)
        (printf (display-list pc2_table 3 6))
        (printf "@section{K1-K16[~a]}\n" key)
        (printf (display-list
                 (map
                  (lambda (k)
                    (foldr (lambda (a b) (string-append a " " b)) "" (split-string k 6)))
                  k_list)
                 57 1))
        ))))


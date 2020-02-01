#lang racket

(require "express-lib.rkt")

(provide (contract-out
          [write-report-key-and-iv (-> string? (listof string?) string? path-string? void?)]
          ))

(define (write-report-key-and-iv key key_b8_list iv_bin express_path)
  (let* ([scrbl_dir (build-path express_path "key-and-iv")]
         [file_name (format "key-and-iv-~a.scrbl" key)]
         [scrbl_file (build-path scrbl_dir file_name)])

    (with-output-to-file
        (build-path express_path "report.scrbl") #:exists 'append
        (lambda ()
          (printf "@include-section[\"key-and-iv/~a\"]\n\n" file_name)))

    (make-directory* scrbl_dir)

    (with-output-to-file
        scrbl_file
      (lambda ()
        (printf "#lang scribble/base\n\n")
        (printf "@title{Key And Iv[~a]}\n\n" key)
        (printf "@section{Origin Key[~a]}\n" key)
        (printf "[~a]\n" key)
        (printf "@section{Key To Binary[~a]}\n\n" key)
        (printf "length: ~a\n\n" (string-length key))
        (printf (display-list key_b8_list 10))
        (printf "@section{Origin Iv[~a]}\n\n" key)
        (printf "[~a]\n\n" iv_bin)
        ))))


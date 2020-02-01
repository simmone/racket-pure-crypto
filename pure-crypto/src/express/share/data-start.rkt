#lang racket

(require "express-lib.rkt")
(require "../../lib/lib.rkt")

(provide (contract-out
          [write-report-data-start-groups (-> string? symbol? (listof string?) (listof string?) path-string? void?)]
          ))

(define (write-report-data-start-groups origin_data data_format? hex_list 64bit_list express_path)
  (let* ([scrbl_dir (build-path express_path "data-start-groups")]
         [scrbl_file (build-path scrbl_dir "data-start-groups.scrbl")])

    (with-output-to-file
        (build-path express_path "report.scrbl") #:exists 'append
        (lambda ()
          (printf "@include-section[\"data-start-groups/data-start-groups.scrbl\"]\n\n")))

    (make-directory* scrbl_dir)

    (with-output-to-file
        scrbl_file
      (lambda ()
        (printf "#lang scribble/base\n\n")
        (printf "@title{Data Start}\n\n")
        (printf "@section{Origin Data:}\n")
        (printf "[~a][~a]\n\n" data_format? origin_data)
        (printf "@section{Hex Blocks:}\n")
        (printf (display-list hex_list 10 1))
        (printf "@section{Bit Blocks:}\n")
        (printf (display-list 64bit_list 10 1))
        ))))


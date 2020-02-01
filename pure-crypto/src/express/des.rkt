#lang racket

(require "share/express-lib.rkt")
(require "../lib/lib.rkt")

(provide (contract-out
          [write-report-des-start (-> (listof natural?) (listof natural?) (listof natural?) symbol? path-string? void?)]
          [write-report-des-data-after-padding (-> (listof string?) (listof string?) path-string? void?)]
          [write-report-des-block-start (-> natural? string? string? path-string? void?)]
          [write-report-des-permuted (-> natural? string? string? string? string? path-string? void?)]
          [write-report-des-cbc-operation (-> natural? string? string? string? path-string? void?)]
          [write-report-des-pcbc-operation (-> natural? string? string? string? string? path-string? void?)]
          [write-report-des-cofb-operation (-> string? string? string? path-string? void?)]
          [write-report-des-step (->
                                     natural?
                                     natural?
                                     string?
                                     string?
                                     string?
                                     string?
                                     string?
                                     string?
                                     string?
                                     string?
                                     path-string?
                                     void?)]
          [write-report-des-final (-> natural? string? string? path-string? void?)]
          [write-report-des-end (-> (listof string?) string? symbol? string? path-string? void?)]
          ))

(define (write-report-des-start ip_table e_table ip1_table operation_mode express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        (build-path express_path "report.scrbl") #:exists 'append
        (lambda ()
          (printf "@include-section[\"data/data.scrbl\"]\n\n")))

    (make-directory* scrbl_dir)

    (with-output-to-file
        scrbl_file
      (lambda ()
        (printf "#lang scribble/base\n\n")
        (printf "@title{Des Each 64bits Blocks/~a}\n\n" operation_mode)
        (printf "@section{IP Table}\n")
        (printf (display-list ip_table 3 8))
        (printf "@section{E Table}\n")
        (printf (display-list e_table 3 6))
        (printf "@section{IP1 Table}\n")
        (printf (display-list ip1_table 3 8))
        ))))

(define (write-report-des-data-after-padding hex_list 64bit_list express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "@section{Hex Data After Pading}\n")
        (printf (display-list hex_list 10 1))
        (printf "@section{Bit Blocks After Padding}\n")
        (printf (display-list 64bit_list 10 1))
        ))))

(define (write-report-des-block-start block_index block_bin last_factor express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "@section{Block: [~a]}\n" block_index)
        (printf "block bin:\n~a\n\n" (display-list (split-string block_bin 8) 9 8))
        (printf "last_factor:\n~a\n\n" (display-list (split-string last_factor 8) 9 8))))))

(define (write-report-des-permuted block_index m0 ip0 l0 r0 express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
        (lambda ()
          (printf (display-list
                   (split-string ip0 4)
                   7
                   16))

          (printf "Cipher Start\n\n")

          (printf "L0/R0: [~a]\n" block_index)
          (printf (display-double-list
                   (split-string l0 4)
                   (split-string r0 4)
                   7
                   8))))))

(define (write-report-des-cbc-operation block_index iv_bin block_bin operated_bin express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "[~a]CBC operation detail:\n\n" block_index)
        (printf "iv xor block:\n\n~a\n~a\n~a\n\n" iv_bin block_bin operated_bin)))))

(define (write-report-des-pcbc-operation block_index iv_bin last_block_bin block_bin operated_bin express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "[~a]PCBC operation detail:\n\n" block_index)
        (let ([step1 (~r #:base 2 #:min-width 64 #:pad-string "0" 
                         (bitwise-xor (string->number iv_bin 2) (string->number last_block_bin 2)))])
          (printf "iv xor last_block:\n\n~a\n~a\n~a\n\n"
                  iv_bin
                  last_block_bin 
                  step1)
          (printf "last_result xor block:\n\n~a\n~a\n~a\n\n" step1 block_bin operated_bin))))))

(define (write-report-des-cofb-operation encrypted_bin block_bin result_bin express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "CFB/OFB operation detail:\n\n")
        (printf "encrypted_data xor block:\n\nencrypted:\n\n~a\n\nblock:\n\n~a\n\nresult:\n\n~a\n\n" encrypted_bin block_bin result_bin)))))

(define (write-report-des-step block_index n ln_1 rn_1 en kn kn_xor_en sbn fn rn express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "--------[~a]n: ~a--------\n\n" block_index n)
        (printf "l~a:\n" (sub1 n))
        (printf (display-list (split-string ln_1 4) 5 8))
        (printf "r~a:\n" (sub1 n))
        (printf (display-list (split-string rn_1 4) 5 8))
        (printf "e~a(r~a transformed by e_table):\n" n (sub1 n))
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
        ))))

(define (write-report-des-final block_index r16l16 ip1 express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "final[~a]\n" block_index)
        (printf "r16l16:\n")
        (printf (display-list (split-string r16l16 8) 9 8))
        (printf "ip1:\n")
        (printf (display-list (split-string ip1 8) 9 8))
        (printf "final hex: @bold{~a}\n\n" (string-upcase (~r #:min-width 16 #:base 16 #:pad-string "0" (string->number ip1 2))))

        ))))

(define (write-report-des-end encrypted_binary_list encrypted_hex_data format? final_data express_path)
  (let* ([scrbl_dir (build-path express_path "end")]
         [scrbl_file (build-path scrbl_dir "end.scrbl")])

    (with-output-to-file
        (build-path express_path "report.scrbl") #:exists 'append
        (lambda ()
          (printf "@include-section[\"end/end.scrbl\"]\n\n")))

    (make-directory* scrbl_dir)

    (with-output-to-file
        scrbl_file
      (lambda ()
        (printf "#lang scribble/base\n\n")
        (printf "@title{Encrypted Data}\n\n")
        (printf "encrypted binary list:\n")
        (printf (display-list encrypted_binary_list 65 1))
        (printf "hex:\n")
        (printf (display-list (split-string encrypted_hex_data 16) 17 1))
        (printf "final format:~a\n\n" format?)
        (printf "[~a]\n\n" final_data)
        ))))



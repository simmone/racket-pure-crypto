#lang racket

(require "share/express-lib.rkt")
(require "../lib/lib.rkt")

(provide (contract-out
          [write-report-undes-start (-> (listof natural?) (listof natural?) (listof natural?) (listof natural?) path-string? void?)]
          [write-report-undes-block-start (-> natural? string? string? path-string? void?)]
          [write-report-undes-uncipher-init (-> natural? string? string? string? string? path-string? void?)]
          [write-report-undes-cbc-operation (-> natural? string? string? string? path-string? void?)]
          [write-report-undes-pcbc-operation (-> natural? string? string? string? string? string? path-string? void?)]
          [write-report-undes-cofb-operation (-> natural? string? string? string? path-string? void?)]
          [write-report-undes-step (->
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
          [write-report-undes-final (-> natural? string? string? path-string? void?)]
          [write-report-undes-remove-padding (-> (listof string?) (listof string?) symbol? (listof string?) path-string? void?)]
          [write-report-undes-end (-> string? symbol? string? path-string? void?)]
          ))

(define (write-report-undes-start reversed_ip1_table reversed_ip_table e_table p_table express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        (build-path express_path "report.scrbl") #:exists 'append
        (lambda ()
          (printf "@include-section[\"data/data.scrbl\"]\n\n")))

    (make-directory* scrbl_dir)

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "#lang scribble/base\n\n")
        (printf "@title{UnDes Start}\n")
        (printf "Reversed IP1 Table\n")
        (printf (display-list reversed_ip1_table 3 8))
        (printf "Reversed IP Table\n")
        (printf (display-list reversed_ip_table 3 8))
        (printf "E Table\n")
        (printf (display-list e_table 3 4))
        (printf "P Table\n")
        (printf (display-list p_table 3 4))
        ))))

(define (write-report-undes-block-start block_index encrypted_block_bin last_factor express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "@section{Block: [~a]}\n" block_index)
        (printf "encrypted_block:\n~a\n\n" (display-list (split-string encrypted_block_bin 8) 9 8))
        (printf "last_factor:\n~a\n\n" (display-list (split-string last_factor 8) 9 8))))))

(define (write-report-undes-uncipher-init block_index binary_data ip1 l16 r16 express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "UnCipher Start\n\n")
        (printf "data:\n")
        (printf (display-list (split-string binary_data 8) 9 8))
        (printf "ip1:\n")
        (printf (display-list (split-string ip1 8) 9 8))
        (printf "l16:\n\n")
        (printf (display-list (split-string l16 8) 9 8))
        (printf "r16:\n\n")
        (printf (display-list (split-string r16 8) 9 8))
        ))))

(define (write-report-undes-cbc-operation block_index iv_bin block_bin operated_bin express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "[~a]CBC operation detail:\n\n" block_index)
        (printf "iv xor block:\n\n~a\n~a\n~a\n\n" iv_bin block_bin operated_bin)))))

(define (write-report-undes-cofb-operation block_index encrypted_block decrypted_block operated_bin express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "[~a]CFB operation detail:\n\n" block_index)
        (printf "decrypted block xor encrypted block:\n\n~a\n~a\n~a\n\n" decrypted_block encrypted_block operated_bin)))))
 
(define (write-report-undes-pcbc-operation
         block_index last_factor this_decrypted_result this_decrypted_block this_encrypted_block next_factor express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "[~a]PCBC operation detail:\n\n" block_index)
        (printf "last_factor xor this_decrypted_result = this_decrypted_block:\n\n~a\n~a\n~a\n\n"
                last_factor
                this_decrypted_result
                this_decrypted_block)
        (printf "this_decrypted_block xor this_encrypted_block = next_factor:\n\n~a\n~a\n~a\n\n"
                this_encrypted_block
                this_decrypted_block
                next_factor)))))

(define (write-report-undes-step block_index n ln_1 rn_1 en kn kn_xor_en sbn fn rn express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "--------[~a]n: ~a--------\n\n" block_index n)
        (printf "r~a:\n" n)
        (printf (display-list (split-string rn 4) 5 8))
        (printf "r~a(l~a):\n" (sub1 n) n)
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
        (printf "l~a:\n" (sub1 n))
        (printf (display-list (split-string ln_1 4) 5 8))
        (printf "--------[~a]n: ~a--------\n\n" block_index n)
        ))))

(define (write-report-undes-final block_index l0r0 block_binary_data express_path)
  (let* ([scrbl_dir (build-path express_path "data")]
         [scrbl_file (build-path scrbl_dir "data.scrbl")])

    (with-output-to-file
        scrbl_file #:exists 'append
      (lambda ()
        (printf "final[~a]\n" block_index)
        (printf "l0r0:\n")
        (printf (display-list (split-string l0r0 8) 9 8))
        (printf "block binary:\n")
        (printf (display-list (split-string block_binary_data 8) 9 8))
        ))))

(define (write-report-undes-remove-padding result_binary_list decrypted_hex_strs padding_mode? hex_strs_after_remove_padding express_path)
  (let* ([scrbl_dir (build-path express_path "remove-padding")]
         [scrbl_file (build-path scrbl_dir "remove-padding.scrbl")])

    (with-output-to-file
        (build-path express_path "report.scrbl") #:exists 'append
        (lambda ()
          (printf "@include-section[\"remove-padding/remove-padding.scrbl\"]\n\n")))

    (make-directory* scrbl_dir)

    (with-output-to-file
        scrbl_file
      (lambda ()
        (printf "#lang scribble/base\n\n")
        (printf "@title{Remove Padding}\n\n")
        (printf "result binary and hex:\n")
        (printf (display-double-list result_binary_list decrypted_hex_strs 17 1))
        (printf "padding mode:~a\n\n" padding_mode?)
        (printf "hex after remove padding:\n")
        (printf (display-list hex_strs_after_remove_padding 17 1))
        ))))

(define (write-report-undes-end decrypted_hex_data format? final_data express_path)
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
        (printf "@title{Decrypted Data}\n\n")
        (printf "final hex:\n")
        (printf (display-list (split-string decrypted_hex_data 16) 17 1))
        (printf "final format:~a\n\n" format?)
        (printf "data:[~a]\n" final_data)
        ))))




#lang racket

(require "lib/constants.rkt")
(require "lib/lib.rkt")
(require "lib/padding.rkt")
(require "lib/process-key.rkt")
(require "lib/process-data.rkt")
(require "cipher/des.rkt")
(require "share.rkt")

(require file/sha1)
(require net/base64)

(provide (contract-out
          [encrypt (->* (string? string?)
                    (
                     #:type? (or/c 'des 'tdes 'aes)
                     #:key_format? (or/c 'hex 'base64 'utf-8)
                     #:data_format? (or/c 'hex 'base64 'utf-8)
                     #:encrypted_format? (or/c 'hex 'base64)
                     #:padding_mode? (or/c 'pkcs5 'zero 'no-padding 'ansix923 'iso10126)
                     #:operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb)
                     #:iv? string?
                     #:detail? (or/c #f (listof (or/c 'raw 'console path-string?)))
                    )
                    string?)]
          ))

(define (encrypt 
         data key
         #:type? [type? 'des]
         #:key_format? [key_format? 'utf-8]
         #:data_format? [data_format? 'utf-8]
         #:encrypted_format? [encrypted_format? 'hex]
         #:padding_mode? [padding_mode? 'pkcs5]
         #:operation_mode? [operation_mode? 'cbc]
         #:iv? [iv? "0000000000000000"]
         #:detail? [detail? #f]
         )
  (detail 
   #:formats detail?
   #:exception_value #f
   (lambda ()

     (detail-page
      (lambda ()
        (detail-h1 "Encryption Detail")

        (define key_and_iv (process-key key #:iv? iv? #:key_format? key_format?))

        (define k_lists (car key_and_iv))
        (define iv_bin (cdr key_and_iv))

        (define hex_and_bits 
          (process-data
           data
           #:data_format? data_format?
           #:padding_mode? padding_mode?
           #:operation_mode? operation_mode?))
        (define hex_strs_after_padding (car hex_and_bits))
        (define 64bits_blocks_after_padding (cdr hex_and_bits))

        (define reverse_ip_1_table (reverse-table *ip_1_table*))
        (define reverse_ip_table (reverse-table *ip_table*))))

     (detail-page
      (lambda ()
        (detail-h2 "Block Processing")

        (let loop ([blocks 64bits_blocks_after_padding]
                   [block_index 1]
                   [last_result iv_bin]
                   [last_origin_bin (hex-string->binary-string "0000000000000000")]
                   [result_list '()])
          (if (not (null? blocks))
              (let* ([block_binary_data (car blocks)]
                     [operated_binary_data  #f]
                     [encrypted_block_binary_data #f]
                     [result_binary_data #f])

          (express express? (lambda () (write-report-des-block-start block_index block_binary_data last_result express_path?)))

          (cond
           [(eq? operation_mode? 'ecb)
            (set! operated_binary_data block_binary_data)]
           [(eq? operation_mode? 'cbc)
            (set! operated_binary_data
                  (~r #:base 2 #:min-width 64 #:pad-string "0" (bitwise-xor (string->number last_result 2) (string->number block_binary_data 2))))]
           [(eq? operation_mode? 'pcbc)
            (set! operated_binary_data
                  (let* ([step1 (bitwise-xor (string->number last_result 2) (string->number last_origin_bin 2))]
                         [step2 (bitwise-xor (string->number block_binary_data 2) step1)])
                    (~r #:base 2 #:min-width 64 #:pad-string "0" step2)))]
           [(or
             (eq? operation_mode? 'cfb)
             (eq? operation_mode? 'ofb))
            (set! operated_binary_data last_result)]
           [else
            (set! operated_binary_data block_binary_data)])

          (express
           express?
           (lambda ()
             (cond
              [(eq? operation_mode? 'cbc)
               (write-report-des-cbc-operation block_index last_result block_binary_data operated_binary_data express_path?)]
              [(eq? operation_mode? 'pcbc)
               (write-report-des-pcbc-operation block_index last_result last_origin_bin block_binary_data operated_binary_data express_path?)])))
          
          (set! encrypted_block_binary_data
                (if (eq? type? 'des)
                    (encryption block_index (list-ref k_lists 0) operated_binary_data express? express_path?)
                    (let ([e1 #f]
                          [ed2 #f])
                      (set! e1 (encryption block_index (list-ref k_lists 0) operated_binary_data express? express_path?))
                      (set! ed2 (decryption block_index reverse_ip_1_table reverse_ip_table (list-ref k_lists 1) e1 express? express_path?))
                      (encryption block_index (list-ref k_lists 2) ed2 express? express_path?))))

          (set! result_binary_data
                (cond
                 [(or
                   (eq? operation_mode? 'cfb)
                   (eq? operation_mode? 'ofb))
                  (let* ([padding_before_xor (~a #:min-width 64 #:right-pad-string "0" block_binary_data)]
                         [cofb_xor_result
                          (~r #:min-width 64 #:base 2 #:pad-string "0"
                              (bitwise-xor (string->number encrypted_block_binary_data 2) (string->number padding_before_xor 2)))])
                    (if (not (= (string-length block_binary_data) 64))
                        (substring cofb_xor_result 0 (string-length block_binary_data))
                        cofb_xor_result))]
                 [else
                  encrypted_block_binary_data]))

          (express
           express?
           (lambda ()
             (cond
              [(or
                (eq? operation_mode? 'cfb)
                (eq? operation_mode? 'ofb))
               (write-report-des-cofb-operation encrypted_block_binary_data block_binary_data result_binary_data express_path?)])))

          (loop
           (cdr blocks)
           (add1 block_index)
           (cond
            [(eq? operation_mode? 'ofb)
             encrypted_block_binary_data]
            [else
             result_binary_data])
           block_binary_data
           (cons
            result_binary_data
            result_list)))
        (let* ([encrypted_binary_data_list (reverse result_list)]
               [encrypted_data
                (foldr string-append ""
                       (map
                        (lambda (binary_data)
                          (string-upcase
                           (~r #:base 16 #:min-width (/ (string-length binary_data) 4) #:pad-string "0" (string->number binary_data 2))))
                        encrypted_binary_data_list))]
               [final_data
                (cond
                 [(eq? encrypted_format? 'base64)
                  (bytes->string/utf-8 (base64-encode (hex-string->bytes encrypted_data)))]
                 [else
                  encrypted_data])])
          (express express? (lambda () (write-report-des-end encrypted_binary_data_list encrypted_data encrypted_format? final_data express_path?)))
          final_data))))

#lang racket

(require "lib/constants.rkt")
(require "lib/lib.rkt")
(require "lib/padding.rkt")
(require "lib/to-hex-key.rkt")
(require "lib/process-data.rkt")
(require "cipher/des/des.rkt")
(require "cipher/des/des-key-lists.rkt")
(require "cipher/aes/aes.rkt")

(require "../../../racket-detail/detail/main.rkt")

(require file/sha1)
(require net/base64)

(provide (contract-out
          [encrypt (->* (string? string?)
                    (
                     #:cipher? (or/c 'des 'tdes 'aes)
                     #:key_format? (or/c 'hex 'base64 'utf-8)
                     #:data_format? (or/c 'hex 'base64 'utf-8)
                     #:encrypted_format? (or/c 'hex 'base64)
                     #:padding_mode? (or/c 'pkcs5 'zero 'no-padding 'ansix923 'iso10126)
                     #:operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb)
                     #:iv? string?
                     #:detail? (or/c #f (listof (or/c 'raw 'console path-string?)))
                    )
                    (or/c #f string?))]
          ))

(define (encrypt 
         data key
         #:cipher? [cipher? 'des]
         #:key_format? [key_format? 'utf-8]
         #:data_format? [data_format? 'utf-8]
         #:encrypted_format? [encrypted_format? 'hex]
         #:padding_mode? [padding_mode? 'pkcs5]
         #:operation_mode? [operation_mode? 'cbc]
         #:iv? [iv? "0000000000000000"]
         #:detail? [detail? #f]
         )
  (detail 
   #:formats? detail?
   #:exception_value? #f
   (lambda ()

     (let ([des_k_lists #f]
           [hex_key #f]
           [iv_bin #f]
           [64bits_blocks_after_padding #f])

       (detail-page
        (lambda ()
          (detail-h1 (format "~a Encryption Detail" (string-upcase (symbol->string cipher?))))

          (set! hex_key (to-hex-key key #:cipher? cipher? #:key_format? key_format?))

          (cond
           [(or (eq? cipher? 'des) (eq? cipher? 'tdes))
            (set! des_k_lists (des-key-lists key #:key_format? key_format?))])

          (detail-line (format "iv:[~a]" iv?))
          (set! iv_bin (~r #:min-width 64 #:base 2 #:pad-string "0" (string->number iv? 16)))
          (detail-line (format "iv in binary:[~a]" iv_bin))

          (define hex_and_bits 
            (process-data
             data
             #:data_format? data_format?
             #:padding_mode? padding_mode?
             #:operation_mode? operation_mode?))
          (define hex_strs_after_padding (car hex_and_bits))
          (set! 64bits_blocks_after_padding (cdr hex_and_bits))))

       (detail-page
        #:line_break_length? 32
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

                  (detail-line (format "----block index:[~a]----" block_index))
                  (detail-line "block_binary_data:")
                  (detail-line block_binary_data #:line_break_length? 8)

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

                  (detail-line "last_result:")
                  (detail-line last_result)
                  (detail-line "last_origin_bin:")
                  (detail-line last_origin_bin)
                  (detail-line "operated_binary_data:")
                  (detail-line operated_binary_data)

                  (set! encrypted_block_binary_data
                        (cond
                         [(eq? cipher? 'des)
                          (des operated_binary_data (list-ref des_k_lists 0))]
                         [(eq? cipher? 'tdes)
                          (let ([e1 #f]
                                [ed2 #f])
                            (set! e1 (des operated_binary_data (list-ref des_k_lists 0)))
                            (set! ed2 (undes e1 (list-ref des_k_lists 1)))
                            (des ed2 (list-ref des_k_lists 2)))]
                         [(eq? cipher? 'aes)
                          (aes operated_binary_data hex_key)]
                         ))

                  (detail-line "encrypted_block_binary_data:")
                  (detail-line encrypted_block_binary_data #:line_break_length? 64 #:font_size? 'small)

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

                  (when (or
                         (eq? operation_mode? 'cfb)
                         (eq? operation_mode? 'ofb))

                    (detail-line "result_binary_data:")
                    (detail-line result_binary_data))

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
                  (detail-line "encrypted_binary_data_list:")
                  (detail-simple-list encrypted_binary_data_list #:cols_count? 1 #:font_size? 'small)

                  (detail-line "encryted_hex_data:")
                  (detail-line encrypted_data #:line_break_length? 16)

                  (detail-line (format "encryted_format?:[~a]" encrypted_format?))

                  (detail-line final_data #:line_break_length? 16)

                  final_data)))))))))

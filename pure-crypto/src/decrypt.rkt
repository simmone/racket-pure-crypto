#lang racket

(require file/sha1)
(require net/base64)

(require "lib/constants.rkt")
(require "lib/lib.rkt")
(require "lib/padding.rkt")
(require "cipher/undes.rkt")

(require "../../../racket-detail/detail/main.rkt")

(provide (contract-out
          [decrypt (->* (string? string?)
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
                      string?)]
          ))

(define (decrypt data key
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
   #:formats detail?
   #:exception_value #f
   (lambda ()

     (let ([k_lists #f]
           [iv_bin #f]
           [64bits_blocks_after_padding #f])

     (detail-page
      (lambda ()
        (detail-h1 "Decryption Detail")

        (define key_and_iv (process-key key iv? key_format? express? express_path?))

        (set! k_lists (car key_and_iv))
        (set! iv_bin (cdr key_and_iv))
  
        (define hex_and_bits
          (process-data data
            (process-data
             data
             #:data_format? data_format?
             #:padding_mode? padding_mode?
             #:operation_mode? operation_mode?)))

        (define hex_strs_after_padding (car hex_and_bits))
        (set! 64bits_blocks_after_padding (cdr hex_and_bits))))

        (detail-page
          #:line_break_length 32
          (lambda ()
            (detail-h2 "Block Processing")

            (let loop ([loop_blocks 64bits_blocks_after_padding]
                       [block_index 1]
                       [last_factor iv_bin]
                       [result_list '()])
              (if (not (null? loop_blocks))
                  (let* ([encrypted_block_data (car loop_blocks)]
                         [decrypted_block_data #f]
                         [operated_decrypted_block_data #f]
                         [operation_next_factor #f])

                  (detail-line (format "----block index:[~a]----" block_index))
                  (detail-line "encypted_block_data:")
                  (detail-line encypted_block_data: #:line_break_length 8)

                  (detail-line "last_factor:")
                  (detail-line last_factor)

                  (set! decrypted_block_data
                        (if (or
                             (eq? operation_mode? 'cfb)
                             (eq? operation_mode? 'ofb))
                            (if (eq? type? 'des)
                                (encryption last_factor (list-ref k_lists 0))
                                (let ([e1 #f]
                                      [ed2 #f])
                                  (set! e1 (encryption last_factor (list-ref k_lists 0)))
                                  (set! ed2 (decryption e1 (list-ref k_lists 1)))
                                  (encryption ed2 (list-ref k_lists 2))))
                            (if (eq? type? 'des)
                                (decryption encrypted_block_data (list-ref k_lists 0))
                                (let ([d1 #f]
                                      [de2 #f])
                                  (set! d1 (decryption encrypted_block_data (list-ref k_lists 2)))
                                  (set! de2 (encryption d1 (list-ref k_lists 1)))
                                  (decryption de2 (list-ref k_lists 0))))))
          
          (set! operated_decrypted_block_data
                (cond
                 [(eq? operation_mode? 'cbc)
                  (let ([result
                         (~r #:base 2 #:min-width 64 #:pad-string "0"
                             (bitwise-xor (string->number last_factor 2)
                                          (string->number decrypted_block_data 2)))])

                    (set! operation_next_factor encrypted_block_data)

                    (express
                     express?
                     (lambda ()
                       (write-report-undes-cbc-operation block_index operation_next_factor decrypted_block_data result express_path?)))
                  result)]
                 [(eq? operation_mode? 'pcbc)
                  (let* ([pcbc_decrypted_block (bitwise-xor (string->number last_factor 2) (string->number decrypted_block_data 2))]
                         [pcbc_decrypted_binary_data (~r #:base 2 #:min-width 64 #:pad-string "0" pcbc_decrypted_block)]
                         [pcbc_next_factor_binary (~r #:base 2 #:min-width 64 #:pad-string "0"
                                                      (bitwise-xor (string->number encrypted_block_data 2) pcbc_decrypted_block))])

                    (set! operation_next_factor pcbc_next_factor_binary)

                    (express
                     express?
                     (lambda ()
                       (write-report-undes-pcbc-operation
                        block_index
                        operation_next_factor
                        decrypted_block_data
                        pcbc_decrypted_binary_data
                        encrypted_block_data
                        pcbc_next_factor_binary
                        express_path?)))

                    pcbc_decrypted_binary_data)]
                 [(or (eq? operation_mode? 'cfb) (eq? operation_mode? 'ofb))
                  (let* ([count (string-length encrypted_block_data)]
                         [padding_before_xor (~a #:min-width 64 #:right-pad-string "0" encrypted_block_data)]
                         [result
                          (substring
                           (~r #:min-width 64 #:base 2 #:pad-string "0"
                               (bitwise-xor (string->number decrypted_block_data 2) (string->number padding_before_xor 2)))
                           0 count)])

                    (if (eq? operation_mode? 'cfb)
                        (set! operation_next_factor encrypted_block_data)
                        (set! operation_next_factor decrypted_block_data))

                    (express
                     express?
                     (lambda ()
                       (write-report-undes-cofb-operation block_index padding_before_xor decrypted_block_data result express_path?)))
                  result)]
                 [else
                  decrypted_block_data]))

          (loop
           (cdr loop_blocks)
           (add1 block_index)
           operation_next_factor
           (cons operated_decrypted_block_data result_list)))
        (let ([decrypted_data_hex_strs
               (map
                (lambda (binary_data)
                  (string-upcase
                   (~r #:base 16 #:min-width (/ (string-length binary_data) 4) #:pad-string "0" (string->number binary_data 2))))
                (reverse result_list))])

          (define hex_strs_after_remove_padding
            (if (and
                 (not (eq? operation_mode? 'cfb))
                 (not (eq? operation_mode? 'ofb))
                 (= (string-length (last decrypted_data_hex_strs)) 16)
                 (not (eq? padding_mode? 'no-padding)))
                (list-set decrypted_data_hex_strs
                          (sub1 (length decrypted_data_hex_strs))
                          (cond
                           [(eq? padding_mode? 'pkcs5)
                            (unpadding-pkcs5 (last decrypted_data_hex_strs) 64)]
                           [(eq? padding_mode? 'zero)
                            (unpadding-zero (last decrypted_data_hex_strs) 64)]
                           [(eq? padding_mode? 'ansix923)
                            (unpadding-ansix923 (last decrypted_data_hex_strs) 64)]
                           [(eq? padding_mode? 'iso10126)
                            (unpadding-iso10126 (last decrypted_data_hex_strs) 64)]
                           ))
                decrypted_data_hex_strs))

          (express
           express?
           (lambda ()
             (write-report-undes-remove-padding
              (reverse result_list)
              decrypted_data_hex_strs
              padding_mode?
              hex_strs_after_remove_padding
              express_path?)))

          (let* ([decrypted_hex_data
                  (foldr string-append "" hex_strs_after_remove_padding)]
                 [final_data
                  (cond
                   [(eq? data_format? 'utf-8)
                    (bytes->string/utf-8 (hex-string->bytes decrypted_hex_data))]
                   [(eq? data_format? 'base64)
                    (bytes->string/utf-8 (base64-encode (hex-string->bytes decrypted_hex_data)))]
                   [else
                    decrypted_hex_data])])

            (express
             express?
             (lambda ()
               (write-report-undes-end
                decrypted_hex_data
                data_format?
                final_data
                express_path?)))

            final_data)))))

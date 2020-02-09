#lang racket

(require file/sha1)
(require net/base64)

(require "lib/constants.rkt")
(require "lib/lib.rkt")
(require "lib/padding.rkt")
(require "lib/process-key.rkt")
(require "lib/process-data.rkt")
(require "cipher/undes.rkt")
(require "cipher/des.rkt")

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
                      (or/c #f string?))]
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
   #:formats? detail?
   #:exception_value? #f
   (lambda ()

     (let ([k_lists #f]
           [iv_bin #f]
           [64bits_blocks_after_padding #f])

     (detail-page
      (lambda ()
        (detail-h1 "Decryption Detail")

        (define key_and_iv (process-key key #:iv? iv? #:key_format? key_format?))

        (set! k_lists (car key_and_iv))
        (set! iv_bin (cdr key_and_iv))
  
        (define hex_and_bits
          (process-data 
           data
           #:data_format? encrypted_format?
           #:padding_mode? padding_mode?
           #:operation_mode? operation_mode?))

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

                (detail-line "encrypted_block_data:")
                (detail-line encrypted_block_data #:line_break_length? 8)

                (detail-line "last_factor:")
                (detail-line (format "~a" last_factor))

                (detail-line "decrypted_block_data:")
                (set! decrypted_block_data
                      (if (or
                           (eq? operation_mode? 'cfb)
                           (eq? operation_mode? 'ofb))
                          (if (eq? cipher? 'des)
                              (des last_factor (list-ref k_lists 0))
                              (let ([e1 #f]
                                    [ed2 #f])
                                (set! e1 (des last_factor (list-ref k_lists 0)))
                                (set! ed2 (undes e1 (list-ref k_lists 1)))
                                (des ed2 (list-ref k_lists 2))))
                          (if (eq? cipher? 'des)
                              (undes encrypted_block_data (list-ref k_lists 0))
                              (let ([d1 #f]
                                    [de2 #f])
                                (set! d1 (undes encrypted_block_data (list-ref k_lists 2)))
                                (set! de2 (des d1 (list-ref k_lists 1)))
                                (undes de2 (list-ref k_lists 0))))))
                (detail-line decrypted_block_data)

                (detail-line "operated_decrypted_block_data:")
                (set! operated_decrypted_block_data
                      (cond
                       [(eq? operation_mode? 'cbc)
                        (let ([result
                               (~r #:base 2 #:min-width 64 #:pad-string "0"
                                   (bitwise-xor (string->number last_factor 2)
                                                (string->number decrypted_block_data 2)))])
                          
                          (set! operation_next_factor encrypted_block_data)

                          result)]
                       [(eq? operation_mode? 'pcbc)
                        (let* ([pcbc_decrypted_block (bitwise-xor (string->number last_factor 2) (string->number decrypted_block_data 2))]
                               [pcbc_decrypted_binary_data (~r #:base 2 #:min-width 64 #:pad-string "0" pcbc_decrypted_block)]
                               [pcbc_next_factor_binary (~r #:base 2 #:min-width 64 #:pad-string "0"
                                                            (bitwise-xor (string->number encrypted_block_data 2) pcbc_decrypted_block))])

                          (set! operation_next_factor pcbc_next_factor_binary)

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
                          result)]
                       [else
                        decrypted_block_data]))
                (detail-line operated_decrypted_block_data)

                (detail-line "operation_next_factor:")
                (detail-line (format "~a" operation_next_factor))

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

                (detail-line "decrypted_data_hex_strs:")
                (detail-simple-list decrypted_data_hex_strs #:cols_count? 1 #:font_size? 'small)

                (detail-line "hex_strs_after_remove_padding:")
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
                (detail-simple-list hex_strs_after_remove_padding #:cols_count? 1 #:font_size? 'small)

                (let* ([decrypted_hex_data #f]
                       [final_data #f])
                  
                  (detail-line "decrypted_hex_data:")
                  (set! decrypted_hex_data (foldr string-append "" hex_strs_after_remove_padding))
                  (detail-line decrypted_hex_data #:line_break_length? 16)
                  
                  (detail-line "final data:")
                  (set! final_data
                        (cond
                         [(eq? data_format? 'utf-8)
                          (bytes->string/utf-8 (hex-string->bytes decrypted_hex_data))]
                         [(eq? data_format? 'base64)
                          (bytes->string/utf-8 (base64-encode (hex-string->bytes decrypted_hex_data)))]
                         [else
                          decrypted_hex_data]))
                  (detail-line final_data #:line_break_length? 16)

                  final_data))))))))))

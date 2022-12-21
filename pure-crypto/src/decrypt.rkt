#lang racket

(require file/sha1)
(require net/base64)

(require "lib/constants.rkt")
(require "lib/lib.rkt")
(require "lib/padding.rkt")
(require "lib/to-hex-key.rkt")
(require "lib/process-data.rkt")
(require "cipher/des/des.rkt")
(require "cipher/des/des-key-lists.rkt")
(require "cipher/aes/aes.rkt")

(provide (contract-out
          [decrypt (->* (string? string?)
                        (
                         #:cipher? (or/c 'des 'tdes 'aes)
                                   #:key_format? (or/c 'hex 'base64 'utf-8)
                                   #:data_format? (or/c 'hex 'base64 'utf-8)
                                   #:encrypted_format? (or/c 'hex 'base64)
                                   #:padding_mode? (or/c 'pkcs7 'zero 'no-padding 'ansix923 'iso10126)
                                   #:operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb 'ctr)
                                   #:iv? string?
                                   )
                        (or/c #f string?))]
          ))

(define (decrypt data key
                 #:cipher? [cipher? 'des]
                 #:key_format? [key_format? 'utf-8]
                 #:data_format? [data_format? 'utf-8]
                 #:encrypted_format? [encrypted_format? 'hex]
                 #:padding_mode? [padding_mode? 'pkcs7]
                 #:operation_mode? [operation_mode? 'cbc]
                 #:iv? [iv? #f]
                 )

  (let ([des_k_lists #f]
        [hex_key #f]
        [iv_bin #f]
        [block_bit_size #f]
        [block_hex_size #f]
        [block_byte_size #f]
        [bits_blocks_after_padding #f])

    (set! block_bit_size 
          (cond
           [(or (eq? cipher? 'des) (eq? cipher? 'tdes))
            64]
           [(eq? cipher? 'aes)
            128]))
    (set! block_hex_size (/ block_bit_size 4))
    (set! block_byte_size (/ block_bit_size 8))

    (when
        (not
         (cond
          [(or (eq? cipher? 'des) (eq? cipher? 'tdes))
           (when (member operation_mode? '(ecb cbc pcbc cfb ofb))
             #t)]
          [(eq? cipher? 'aes)
           (when (member operation_mode? '(ecb cbc pcbc cfb ofb ctr))
             #t)]
          [else
           #f]))
      (error (format "cipher[~a] can't use this operation_mode[~a]" cipher? operation_mode?)))

    (when (not iv?)
      (set! iv?
            (cond
             [(or (eq? cipher? 'des) (eq? cipher? 'tdes))
              "0000000000000000"]
             [(eq? cipher? 'aes)
              "00000000000000000000000000000000"])))

    (when (not (regexp-match (pregexp (format "^([0-9a-zA-Z]){~a}$" block_hex_size)) iv?))
      (error (format "iv should be in ~a hex format." block_hex_size)))

    (set! iv_bin (~r #:min-width block_bit_size #:base 2 #:pad-string "0" (string->number iv? 16)))
    
    (set! hex_key (to-hex-key key #:cipher? cipher? #:key_format? key_format?))

    (when (or (eq? cipher? 'des) (eq? cipher? 'tdes))
      (set! des_k_lists (des-key-lists key #:key_format? key_format?)))

    (define hex_and_bits 
      (process-data
       data
       block_bit_size
       block_hex_size
       block_byte_size
       #:data_format? encrypted_format?
       #:padding_mode? 'no-padding
       #:operation_mode? operation_mode?))
    (define hex_strs_after_padding (car hex_and_bits))
    (set! bits_blocks_after_padding (cdr hex_and_bits))

    (let loop ([loop_blocks bits_blocks_after_padding]
               [block_index 1]
               [last_factor iv_bin]
               [result_list '()])
      (if (not (null? loop_blocks))
          (let* ([encrypted_block_data (car loop_blocks)]
                 [decrypted_block_data #f]
                 [operated_decrypted_block_data #f]
                 [operation_next_factor #f])

            (set! decrypted_block_data
                  (if (or
                       (eq? operation_mode? 'cfb)
                       (eq? operation_mode? 'ofb)
                       (eq? operation_mode? 'ctr)
                       )
                      (cond
                       [(eq? cipher? 'des)
                        (des last_factor (list-ref des_k_lists 0))]
                       [(eq? cipher? 'tdes)
                        (let ([e1 #f]
                              [ed2 #f])
                          (set! e1 (des last_factor (list-ref des_k_lists 0)))
                          (set! ed2 (undes e1 (list-ref des_k_lists 1)))
                          (des ed2 (list-ref des_k_lists 2)))]
                       [(eq? cipher? 'aes)
                        (~r #:base 2 #:min-width block_bit_size #:pad-string "0"
                            (string->number
                             (aes
                              (~r #:base 16 #:min-width 32 #:pad-string "0" (string->number last_factor 2))
                              hex_key)
                             16))])
                      (cond
                       [(eq? cipher? 'des)
                        (undes encrypted_block_data (list-ref des_k_lists 0))]
                       [(eq? cipher? 'tdes)
                        (let ([e1 #f]
                              [ed2 #f])
                          (set! e1 (undes encrypted_block_data (list-ref des_k_lists 2)))
                          (set! ed2 (des e1 (list-ref des_k_lists 1)))
                          (undes ed2 (list-ref des_k_lists 0)))]
                       [(eq? cipher? 'aes)
                        (~r #:base 2 #:min-width block_bit_size #:pad-string "0"
                            (string->number
                             (unaes
                              (~r #:base 16 #:min-width 32 #:pad-string "0" (string->number encrypted_block_data 2))
                              hex_key)
                             16))])))
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
                   [(or
                     (eq? operation_mode? 'cfb)
                     (eq? operation_mode? 'ofb)
                     (eq? operation_mode? 'ctr))
                    (let* ([count (string-length encrypted_block_data)]
                           [padding_before_xor (~a #:min-width block_bit_size #:right-pad-string "0" encrypted_block_data)]
                           [result
                            (substring
                             (~r #:min-width block_bit_size #:base 2 #:pad-string "0"
                                 (bitwise-xor (string->number decrypted_block_data 2) (string->number padding_before_xor 2)))
                             0 count)])

                      (cond
                       [(eq? operation_mode? 'cfb)
                        (set! operation_next_factor encrypted_block_data)]
                       [(eq? operation_mode? 'ctr)
                        (set! operation_next_factor
                              (~r #:min-width block_bit_size #:base 2 #:pad-string "0" (add1 (string->number last_factor 2))))
                        ]
                       [else
                        (set! operation_next_factor decrypted_block_data)])
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
                    (if (or
                         (eq? operation_mode? 'cfb)
                         (eq? operation_mode? 'ofb)
                         (eq? operation_mode? 'ctr)
                         )
                        (~r #:base 16 (string->number binary_data 2))                            
                        (~r #:base 16 #:min-width block_hex_size #:pad-string "0" (string->number binary_data 2))))
                  (reverse result_list))])

            (define hex_strs_after_remove_padding
              (if (and
                   (not (eq? operation_mode? 'cfb))
                   (not (eq? operation_mode? 'ofb))
                   (not (eq? operation_mode? 'ctr))
                   (= (string-length (last decrypted_data_hex_strs)) block_hex_size)
                   (not (eq? padding_mode? 'no-padding)))
                  (list-set decrypted_data_hex_strs
                            (sub1 (length decrypted_data_hex_strs))
                            (cond
                             [(eq? padding_mode? 'pkcs7)
                              (unpadding-pkcs7 (last decrypted_data_hex_strs) block_bit_size)]
                             [(eq? padding_mode? 'zero)
                              (unpadding-zero (last decrypted_data_hex_strs) block_bit_size)]
                             [(eq? padding_mode? 'ansix923)
                              (unpadding-ansix923 (last decrypted_data_hex_strs) block_bit_size)]
                             [(eq? padding_mode? 'iso10126)
                              (unpadding-iso10126 (last decrypted_data_hex_strs) block_bit_size)]
                             ))
                  decrypted_data_hex_strs))

            (let* ([decrypted_hex_data #f]
                   [final_data #f])
              
              (set! decrypted_hex_data (string-downcase (foldr string-append "" hex_strs_after_remove_padding)))

              (set! final_data
                    (cond
                     [(eq? data_format? 'utf-8)
                      (bytes->string/utf-8 (hex-string->bytes decrypted_hex_data))]
                     [(eq? data_format? 'base64)
                      (bytes->string/utf-8 (base64-encode (hex-string->bytes decrypted_hex_data)))]
                     [else
                      decrypted_hex_data]))

              final_data))))))

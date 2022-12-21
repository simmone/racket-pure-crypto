#lang racket

(require "lib/constants.rkt")
(require "lib/lib.rkt")
(require "lib/padding.rkt")
(require "lib/to-hex-key.rkt")
(require "lib/process-data.rkt")
(require "cipher/des/des.rkt")
(require "cipher/des/des-key-lists.rkt")
(require "cipher/aes/aes.rkt")

(require file/sha1)
(require net/base64)

(provide (contract-out
          [encrypt (->* (string? string?)
                    (
                     #:cipher? (or/c 'des 'tdes 'aes)
                     #:key_format? (or/c 'hex 'base64 'utf-8)
                     #:data_format? (or/c 'hex 'base64 'utf-8)
                     #:encrypted_format? (or/c 'hex 'base64)
                     #:padding_mode? (or/c 'pkcs7 'zero 'no-padding 'ansix923 'iso10126)
                     #:operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb 'ctr)
                     #:iv? (or/c #f string?)
                    )
                    (or/c #f string?))]
          ))

(define (encrypt 
         data key
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
       #:data_format? data_format?
       #:padding_mode? padding_mode?
       #:operation_mode? operation_mode?))
    (define hex_strs_after_padding (car hex_and_bits))
    (set! bits_blocks_after_padding (cdr hex_and_bits))

    (let loop ([blocks bits_blocks_after_padding]
               [block_index 1]
               [last_result iv_bin]
               [last_origin_bin
                (cond
                       [(or (eq? cipher? 'des) (eq? cipher? 'tdes))
                        (hex-string->binary-string "0000000000000000")]
                       [(eq? cipher? 'aes)
                        (hex-string->binary-string "00000000000000000000000000000000")])]
                     [result_list '()])
            (if (not (null? blocks))
                (let* ([block_binary_data (car blocks)]
                       [operated_binary_data  #f]
                       [encrypted_block_binary_data #f]
                       [result_binary_data #f])

                  (cond
                   [(eq? operation_mode? 'ecb)
                    (set! operated_binary_data block_binary_data)]
                   [(eq? operation_mode? 'cbc)
                    (set! operated_binary_data
                          (~r #:base 2 #:min-width block_bit_size #:pad-string "0" (bitwise-xor (string->number last_result 2) (string->number block_binary_data 2))))]
                   [(eq? operation_mode? 'pcbc)
                    (set! operated_binary_data
                          (let* ([step1 (bitwise-xor (string->number last_result 2) (string->number last_origin_bin 2))]
                                 [step2 (bitwise-xor (string->number block_binary_data 2) step1)])
                            (~r #:base 2 #:min-width block_bit_size #:pad-string "0" step2)))]
                   [(or
                     (eq? operation_mode? 'cfb)
                     (eq? operation_mode? 'ofb)
                     (eq? operation_mode? 'ctr)
                     )
                    (set! operated_binary_data last_result)]
                   [else
                    (set! operated_binary_data block_binary_data)])

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
                          (~r #:base 2 #:min-width block_bit_size #:pad-string "0"
                              (string->number
                               (aes
                                (~r #:base 16 #:min-width 32 #:pad-string "0" (string->number operated_binary_data 2))
                                hex_key)
                               16))]
                         ))

                  (set! result_binary_data
                        (cond
                         [(or
                           (eq? operation_mode? 'cfb)
                           (eq? operation_mode? 'ofb)
                           (eq? operation_mode? 'ctr))
                          (let* ([padding_before_xor (~a #:min-width block_bit_size #:right-pad-string "0" block_binary_data)]
                                 [cofb_xor_result
                                  (~r #:min-width block_bit_size #:base 2 #:pad-string "0"
                                      (bitwise-xor (string->number encrypted_block_binary_data 2) (string->number padding_before_xor 2)))])
                            (if (not (= (string-length block_binary_data) block_bit_size))
                                (substring cofb_xor_result 0 (string-length block_binary_data))
                                cofb_xor_result))]
                         [else
                          encrypted_block_binary_data]))

                  (loop
                   (cdr blocks)
                   (add1 block_index)
                   (cond
                    [(eq? operation_mode? 'ofb)
                     encrypted_block_binary_data]
                    [(eq? operation_mode? 'ctr)
                     (~r #:min-width block_bit_size #:base 2 #:pad-string "0"
                         (+ (string->number iv_bin 2) block_index))]
                    [else
                     result_binary_data])
                   block_binary_data
                   (cons
                    result_binary_data
                    result_list)))

                (let ([encrypted_binary_data_list #f]
                      [encrypted_data #f]
                      [final_data #f])

                  (set! encrypted_binary_data_list (reverse result_list))

                  (set! encrypted_data
                        (foldr string-append ""
                               (map
                                (lambda (binary_data)
                                  (string-downcase
                                   (~r #:base 16 #:min-width (/ (string-length binary_data) 4) #:pad-string "0" (string->number binary_data 2))))
                                encrypted_binary_data_list)))

                  (set! final_data
                        (cond
                         [(eq? encrypted_format? 'base64)
                          (bytes->string/utf-8 (base64-encode (hex-string->bytes encrypted_data)))]
                         [else
                          encrypted_data]))

                  final_data)))))

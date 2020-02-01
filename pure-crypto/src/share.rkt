#lang racket

(require file/sha1)
(require net/base64)

(provide (contract-out
          [process-data (-> string? symbol? symbol? symbol? boolean? path-string? (cons/c (listof string?) (listof string?)))]
          [process-key (-> string? string? symbol? boolean? path-string? (cons/c (listof (listof string?)) string?))]
          [encryption (-> natural? (listof string?) string? boolean? path-string? string?)]
          [decryption (-> natural? (listof natural?) (listof natural?) (listof string?) string? boolean? path-string? string?)]
          ))

(require "lib/constants.rkt")
(require "lib/lib.rkt")
(require "lib/padding.rkt")
(require "express/express.rkt")

(define (process-key key iv? key_format? express? express_path?)
  (when (not (regexp-match #px"^([0-9a-zA-Z]){16}$" iv?))
    (error "iv should be in 16 hex format."))

  (define iv_bin (~r #:min-width 64 #:base 2 #:pad-string "0" (string->number iv? 16)))

  (define hex_key
    (string-upcase
     (cond
      [(eq? key_format? 'utf-8)
       (bytes->hex-string (string->bytes/utf-8 key))]
      [(eq? key_format? 'base64)
       (bytes->hex-string (base64-decode (string->bytes/utf-8 key)))]
      [else
       key])))

  (when (and
         (not (= (string-length hex_key) 16))
         (not (= (string-length hex_key) 32))
         (not (= (string-length hex_key) 48)))
    (error (format "key length is invalid. expect 16/32/48(hex), but get ~a" (string-length hex_key))))
  
  (define hex_keys
    (cond
     [(= (string-length hex_key) 16)
      (list (substring hex_key 0 16))]
     [(= (string-length hex_key) 32)
      (list
       (substring hex_key 0 16)
       (substring hex_key 16 32)
       (substring hex_key 0 16))]
     [(= (string-length hex_key) 48)
      (list
       (substring hex_key 0 16)
       (substring hex_key 16 32)
       (substring hex_key 32 48))]))
  
  (cons
   (let loop-keys ([loop_keys hex_keys]
                   [k_lists '()])
     (if (not (null? loop_keys))
         (let ([key_b8_list #f]
               [key_56b #f]
               [key_56b_list #f]
               [c0 #f]
               [d0 #f]
               [c_list #f]
               [d_list #f]
               [k_list #f])
           (set! key_b8_list (hex-string->binary-string-list (car loop_keys) 8))
           
           (express express? (lambda () (write-report-key-and-iv (car loop_keys) key_b8_list iv_bin express_path?)))
           
           (set! key_56b
             (transform-binary-string
              (hex-string->binary-string (car loop_keys))
              *pc1_table*))
           
           (set! key_56b_list (split-string key_56b 7))
           
           (express express? (lambda () (write-report-key-to-56b (car loop_keys) *pc1_table* key_b8_list key_56b_list express_path?)))
           
           (set! c0 (substring key_56b 0 28))
           (set! d0 (substring key_56b 28))
           
           (set! c_list
             (let loop ([shifts *shift_length_list*]
                        [loop_c c0]
                        [result_list '()])
               (if (not (null? shifts))
                   (let ([next_c (shift-left loop_c (car shifts))])
                     (loop
                      (cdr shifts)
                      next_c
                      (cons next_c result_list)))
                   (reverse result_list))))

           (set! d_list
             (let loop ([shifts *shift_length_list*]
                        [loop_d d0]
                        [result_list '()])
               (if (not (null? shifts))
                   (let ([next_d (shift-left loop_d (car shifts))])
                     (loop
                      (cdr shifts)
                      next_d
                      (cons next_d result_list)))
                   (reverse result_list))))

           (express express? (lambda () (write-report-cd0-cd16 (car loop_keys) *shift_length_list* c0 d0 c_list d_list express_path?)))
           
           (set! k_list
             (let loop ([loop_c_list c_list]
                        [loop_d_list d_list]
                        [result_list '()])
               (if (not (null? loop_c_list))
                   (loop
                    (cdr loop_c_list)
                    (cdr loop_d_list)
                    (cons
                     (transform-binary-string
                      (string-append (car loop_c_list) (car loop_d_list))
                      *pc2_table*)
                     result_list))
                   (reverse result_list))))

           (express express? (lambda () (write-report-k1-k16 (car loop_keys) *pc2_table* k_list express_path?)))
           
           (loop-keys (cdr loop_keys) (cons k_list k_lists)))
         (reverse k_lists)))
   iv_bin))

(define (process-data data data_format? padding_mode? operation_mode? express? express_path?)
  (define data_byte_list
    (if (list? data)
        data
        (cond
         [(eq? data_format? 'hex)
          (bytes->list (hex-string->bytes data))]
         [(eq? data_format? 'utf-8)
          (bytes->list (string->bytes/utf-8 data))]
         [(eq? data_format? 'base64)
          (bytes->list (base64-decode (string->bytes/utf-8 data)))]
         [else
          (bytes->list (hex-string->bytes data))])))

  (when
      (and
       (eq? padding_mode? 'no-padding)
       (not (= (remainder (length data_byte_list) 8) 0))
       (not (eq? operation_mode? 'cfb))
       (not (eq? operation_mode? 'ofb))
       )
    (error "data length is not 8's"))

  (define data_to_hex_strs (split-string (bytes->hex-string (list->bytes data_byte_list)) 16))

  (define hex_strs_after_padding
    (if (and
         (not (eq? operation_mode? 'cfb))
         (not (eq? operation_mode? 'ofb))
         (not (= (string-length (last data_to_hex_strs)) 16))
         (not (eq? padding_mode? 'no-padding)))
        (list-set data_to_hex_strs
                  (sub1 (length data_to_hex_strs))
                  (cond
                   [(eq? padding_mode? 'pkcs5)
                    (padding-pkcs5 (last data_to_hex_strs) 64)]
                   [(eq? padding_mode? 'zero)
                    (padding-zero (last data_to_hex_strs) 64)]
                   [(eq? padding_mode? 'ansix923)
                    (padding-ansix923 (last data_to_hex_strs) 64)]
                   [(eq? padding_mode? 'iso10126)
                    (padding-iso10126 (last data_to_hex_strs) 64)]
                   ))
        data_to_hex_strs))

  (define 64bits_blocks_after_padding
    (map
     (lambda (hex_block)
       (~r #:base 2 #:min-width (* (string-length hex_block) 4) #:pad-string "0" (string->number hex_block 16)))
     hex_strs_after_padding))

  (express express? (lambda () (write-report-data-start-groups data data_format? data_to_hex_strs 64bits_blocks_after_padding express_path?)))

  (cons hex_strs_after_padding 64bits_blocks_after_padding))

(define (encryption block_index k_list operated_binary_data express? express_path?)
  (let* ([m0 operated_binary_data]
         [ip0 (transform-binary-string m0 *ip_table*)]
         [l0 (substring ip0 0 32)]
         [r0 (substring ip0 32)]
         [encrypted_block_binary_data #f])
    (express express? (lambda () (write-report-des-permuted block_index m0 ip0 l0 r0 express_path?)))

    (let loop-encode ([ln_1 l0]
                      [rn_1 r0]
                      [n 1])
      (if (<= n 16)
          (let* ([en (transform-binary-string rn_1 *e_table*)]
                 [kn (list-ref k_list (sub1 n))]
                 [kn_xor_en
                  (~r #:base 2 #:min-width 48 #:pad-string "0"
                      (bitwise-xor (string->number kn 2) (string->number en 2)))]
                 [sbn
                  (let loop-sb ([loop_list (split-string kn_xor_en 6)]
                                [index 1]
                                [result_str ""])
                    (if (not (null? loop_list))
                        (loop-sb (cdr loop_list) (add1 index) (string-append result_str (b6->b4 index (car loop_list))))
                        result_str))]
                 [fn (transform-binary-string sbn *p_table*)]
                 [rn
                  (~r #:base 2 #:min-width 32 #:pad-string "0"
                      (bitwise-xor (string->number ln_1 2) (string->number fn 2)))]
                 )
            (express express? (lambda () (write-report-des-step block_index n ln_1 rn_1 en kn kn_xor_en sbn fn rn express_path?)))
            (loop-encode rn_1 rn (add1 n)))
          (let* ([r16l16 (string-append rn_1 ln_1)]
                 [ip1 (transform-binary-string r16l16 *ip_1_table*)])
            (express express? (lambda () (write-report-des-final block_index r16l16 ip1 express_path?)))
            ip1)))))

(define (decryption block_index reverse_ip1_table reverse_ip_table k_list binary_data express? express_path?)
  (define ip1 (transform-binary-string binary_data reverse_ip1_table))

  (define l16 (substring ip1 32))

  (define r16 (substring ip1 0 32))

  (express express? (lambda () (write-report-undes-uncipher-init block_index binary_data ip1 l16 r16 express_path?)))
  
  (let loop ([rn_1 l16]
             [rn r16]
             [n 16])
    (if (>= n 1)
        (let* ([en (transform-binary-string rn_1 *e_table*)]
               [kn (list-ref k_list (sub1 n))]
               [kn_xor_en
                (~r #:base 2 #:min-width 48 #:pad-string "0"
                    (bitwise-xor (string->number kn 2) (string->number en 2)))]
               [sbn
                (let loop-sb ([loop_list (split-string kn_xor_en 6)]
                              [index 1]
                              [result_str ""])
                  (if (not (null? loop_list))
                      (loop-sb (cdr loop_list) (add1 index) (string-append result_str (b6->b4 index (car loop_list))))
                      result_str))]
               [fn (transform-binary-string sbn *p_table*)]
               [ln_1
                (~r #:base 2 #:min-width 32 #:pad-string "0"
                    (bitwise-xor (string->number rn 2) (string->number fn 2)))])
          (express express? (lambda () (write-report-undes-step block_index n ln_1 rn_1 en kn kn_xor_en sbn fn rn express_path?)))
          (loop
           ln_1
           rn_1
           (sub1 n)))
        (let* ([l0r0 (string-append rn_1 rn)]
               [binary_data (transform-binary-string l0r0 reverse_ip_table)])
          (express express? (lambda () (write-report-undes-final block_index l0r0 binary_data express_path?)))
          binary_data))))

#lang racket

(require file/sha1)
(require net/base64)

(require "../../../../racket-detail/detail/main.rkt")

(require "constants.rkt")
(require "lib.rkt")
(require "padding.rkt")

(provide (contract-out
          [process-data (->*
                         (
                          (or/c (listof byte?) string?)
                          natural?
                          natural?
                          natural?
                         )
                         (
                          #:data_format? (or/c 'hex 'base64 'utf-8)
                          #:padding_mode? (or/c 'pkcs7 'zero 'no-padding 'ansix923 'iso10126)
                          #:operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb)
                          )
                         (cons/c (listof string?) (listof string?)))]
          ))

(define (process-data
         data
         block_bit_size
         block_hex_size
         block_byte_size
         #:data_format? [data_format? 'utf-8]
         #:padding_mode? [padding_mode? 'pkcs7]
         #:operation_mode? [operation_mode? 'cbc])

  (detail-div
   #:font_size? 'small
   #:line_break_length? 100
   (lambda ()
     (detail-h2 "Prepare Data")

     (detail-line (format "data_format:[~a]" data_format?))
     (detail-line (format "operation_mode:[~a]" operation_mode?))

     (detail-line "data:")
     (when (not (list? data))
       (detail-line data))
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
     
     (detail-line "data in byte list:")
     (detail-simple-list
      (map (lambda (b) (~r #:base 2 #:pad-string "0" #:min-width 8 b)) data_byte_list)
      #:cols_count? 8)

     (when
         (and
          (eq? padding_mode? 'no-padding)
          (not (= (remainder (length data_byte_list) block_byte_size) 0))
          (not (eq? operation_mode? 'cfb))
          (not (eq? operation_mode? 'ofb))
          )
       (error (format "data length is not ~a's" block_byte_size)))

     (detail-line "data in hex:")
     (define data_to_hex_strs (split-string (bytes->hex-string (list->bytes data_byte_list)) block_hex_size))
     (detail-simple-list data_to_hex_strs #:cols_count? 2)

     (detail-line (format "padding_mode:[~a]" padding_mode?))
     (detail-line "hex blocks after padding:")
     (define hex_strs_after_padding
       (if (and
            (not (eq? operation_mode? 'cfb))
            (not (eq? operation_mode? 'ofb))
            (not (= (string-length (last data_to_hex_strs)) block_hex_size))
            (not (eq? padding_mode? 'no-padding)))
           (list-set data_to_hex_strs
                     (sub1 (length data_to_hex_strs))
                     (cond
                      [(eq? padding_mode? 'pkcs7)
                       (padding-pkcs7 (last data_to_hex_strs) block_bit_size)]
                      [(eq? padding_mode? 'zero)
                       (padding-zero (last data_to_hex_strs) block_bit_size)]
                      [(eq? padding_mode? 'ansix923)
                       (padding-ansix923 (last data_to_hex_strs) block_bit_size)]
                      [(eq? padding_mode? 'iso10126)
                       (padding-iso10126 (last data_to_hex_strs) block_bit_size)]
                      ))
           data_to_hex_strs))
     (detail-simple-list hex_strs_after_padding #:cols_count? 2)

     (detail-line (format "~a bits blocks after padding:" block_bit_size))
     (define bits_blocks_after_padding
       (map
        (lambda (hex_block)
          (~r #:base 2 #:min-width (* (string-length hex_block) 4) #:pad-string "0" (string->number hex_block 16)))
        hex_strs_after_padding))
     (detail-simple-list bits_blocks_after_padding #:cols_count? 1 #:col_width? 64)

  (cons hex_strs_after_padding bits_blocks_after_padding))))

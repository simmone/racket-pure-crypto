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
                         )
                         (
                          #:data_format? (or/c 'hex 'base64 'utf-8)
                          #:padding_mode? (or/c 'pkcs5 'zero 'no-padding 'ansix923 'iso10126)
                          #:operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb)
                          )
                         (cons/c (listof string?) (listof string?)))]
          ))

(define (process-data
         data
         #:data_format? [data_format? 'utf-8]
         #:padding_mode? [padding_mode? 'pkcs5]
         #:operation_mode? [operation_mode? 'cbc])

  (detail-div
   #:font_size 'small
   #:line_break_length 100
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
      #:cols_count 8)

     (when
         (and
          (eq? padding_mode? 'no-padding)
          (not (= (remainder (length data_byte_list) 8) 0))
          (not (eq? operation_mode? 'cfb))
          (not (eq? operation_mode? 'ofb))
          )
       (error "data length is not 8's"))

     (detail-line "data in hex:")
     (define data_to_hex_strs (split-string (bytes->hex-string (list->bytes data_byte_list)) 16))
     (detail-simple-list data_to_hex_strs #:cols_count 4)

     (detail-line (format "padding_mode:[~a]" padding_mode?))
     (detail-line "hex blocks after padding:")
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
     (detail-simple-list hex_strs_after_padding #:cols_count 4)

     (detail-line "64bits blocks after padding:")
     (define 64bits_blocks_after_padding
       (map
        (lambda (hex_block)
          (~r #:base 2 #:min-width (* (string-length hex_block) 4) #:pad-string "0" (string->number hex_block 16)))
        hex_strs_after_padding))
     (detail-simple-list 64bits_blocks_after_padding #:cols_count 4)

  (cons hex_strs_after_padding 64bits_blocks_after_padding))))

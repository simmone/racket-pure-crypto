#lang scribble/manual

@(require (for-label racket))
@(require (for-label des))

@title{DES/TDES(DESede/TDEA/3DES/TripleDes)}

@author+email["Chen Xiao" "chenxiao770117@gmail.com"]

des is a racket implementation of DES/DESede encryption/decryption.

@defmodule[des]

@table-of-contents[]

@section[#:tag "install"]{Install}

raco pkg install des

@section{DES Encryption}

@defproc[(des
           [data string?]
           [key string?]
           [#:type? type? (or/c 'des 'tdes) 'des]
           [#:data_format? data_format? (or/c 'hex 'utf8 'base64) 'utf8]
           [#:key_format? key_format? (or/c 'hex 'utf8 'base64) 'utf8]
           [#:encrypted_format? encrypted_format? (or/c 'hex 'utf8 'base64) 'utf8]
           [#:operation_mode? operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb) 'cbc]
           [#:padding_mode? padding_mode? (or/c 'no-padding 'pkcs5 'zero 'ansix923 'iso10126) 'pkcs5]
           [#:iv? iv? "0000000000000000"]
           [#:express? express? boolean?]
           [#:express_path? express_path? path-string?]
         )
         string?]{

  des include des and tdes encryption, set 'type to 'tdes to use DESede(3DES) encryption.
  
  data and key has three format choices: utf8 plain text, hex, base64
  
  encryption format has two choices: hex and base64

  key's length should be 8 when utf8, 16 when hex, 14 when base64.
  
  DESede use three times key length of DES: 24 when utf8, 46 when hex, 42 when base64.

  padding_mode? use pkcs5 as default selection.

  set #:express? to true will generate a detail report in express_path.

  into the express folder, @verbatim{scribble --htmls report.scrbl} to generate a detail report.

  Warning: express will generate a set of scribble files, it's very slow, debug usage only.
}

@section{DES Decryption}

@defproc[(undes
           [encrypted_data string?]
           [key string?]
           [#:type? type? (or/c 'des 'tdes) 'des]
           [#:data_format? data_format? (or/c 'hex 'utf8 'base64) 'utf8]
           [#:key_format? key_format? (or/c 'hex 'utf8 'base64) 'utf8]
           [#:encrypted_format? encrypted_format? (or/c 'hex 'utf8 'base64) 'utf8]
           [#:operation_mode? operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb) 'cbc]
           [#:padding_mode? padding_mode? (or/c 'no-padding 'pkcs5 'zero 'ansix923 'iso10126) 'pkcs5]
           [#:iv? iv? "0000000000000000"]
           [#:express? express? boolean?]
           [#:express_path? express_path? path-string?]
         )
         string?]{
  parameters same as encryption.
}

@section{TDES/3DES/TripleDes Encryption}

@defproc[(tdes
           [encrypted_data string?]
           [key string?]
           [#:data_format? data_format? (or/c 'hex 'utf8 'base64) 'utf8]
           [#:key_format? key_format? (or/c 'hex 'utf8 'base64) 'utf8]
           [#:encrypted_format? encrypted_format? (or/c 'hex 'utf8 'base64) 'utf8]
           [#:operation_mode? operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb) 'cbc]
           [#:padding_mode? padding_mode? (or/c 'no-padding 'pkcs5 'zero 'ansix923 'iso10126) 'pkcs5]
           [#:iv? iv? "0000000000000000"]
           [#:express? express? boolean?]
           [#:express_path? express_path? path-string?]
         )
         string?]{
  shortcut to des function with type? = 'tdes
}

@section{TDES/3DES/TripleDes Decryption}

@defproc[(untdes
           [encrypted_data string?]
           [key string?]
           [#:data_format? data_format? (or/c 'hex 'utf8 'base64) 'utf8]
           [#:key_format? key_format? (or/c 'hex 'utf8 'base64) 'utf8]
           [#:encrypted_format? encrypted_format? (or/c 'hex 'utf8 'base64) 'utf8]
           [#:operation_mode? operation_mode? (or/c 'ecb 'cbc 'pcbc 'cfb 'ofb) 'cbc]
           [#:padding_mode? padding_mode? (or/c 'no-padding 'pkcs5 'zero 'ansix923 'iso10126) 'pkcs5]
           [#:iv? iv? "0000000000000000"]
           [#:express? express? boolean?]
           [#:express_path? express_path? path-string?]
         )
         string?]{
  shortcut to undes function with type? = 'tdes
}

@section{Usage}

@codeblock{
#lang racket

(require des)

;; des/undes ecb
(des "chenxiao" "chensihe" #:operation_mode? 'ecb) ;; "E99DAFFBF097826E"
(undes "E99DAFFBF097826E" "chensihe" #:operation_mode? 'ecb) ;; "chenxiao"

;; des/undes ecb data_format: base64 key_format: base64
(des "ASNFZ4mrze8=\r\n" "EzRXeZu83/E=\r\n" #:data_format? 'base64 #:key_format? 'base64 #:operation_mode? 'ecb) ;; "85E813540F0AB405"
(undes "85E813540F0AB405" "EzRXeZu83/E=\r\n" #:data_format? 'base64 #:key_format? 'base64 #:operation_mode? 'ecb) ;; "ASNFZ4mrze8=\r\n"

;; des/undes cbc
(des "a" "chensihe" #:iv? "fffffffffffffff0")  ;; "624EE363AF4BFC4F"
(undes "624EE363AF4BFC4F" "chensihe" #:iv? "fffffffffffffff0")  ;; "a"

;; tdes/untdes ecb
(tdes "chenxiao" "chensihehesichenchenhesi" #:operation_mode? 'ecb) ;; "803B74B5ABD02C32"
(untdes "803B74B5ABD02C32" "chensihehesichenchenhesi" #:operation_mode? 'ecb) ;; "chenxiao"

;; tdes/untdes cbc
(tdes "a" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:padding_mode? 'zero) ;; "6AE1861FBD926B64"
(untdes "6AE1861FBD926B64" "chensihehesichenchenhesi" #:iv? "fffffffffffffff0" #:padding_mode? 'zero) ;; "a"
}
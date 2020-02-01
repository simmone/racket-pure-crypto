#lang racket

(require "share/header.rkt")
(require "share/key-and-iv.rkt")
(require "share/key-to-56b.rkt")
(require "share/cd0-cd16.rkt")
(require "share/k1-k16.rkt")
(require "share/data-start.rkt")
(require "des.rkt")
(require "undes.rkt")

(provide (contract-out
          [express (-> boolean? procedure? void?)]
          [write-report-header (-> string? path-string? void?)]
          [write-report-key-and-iv (-> string? (listof string?) string? path-string? void?)]
          [write-report-key-to-56b (-> string? (listof natural?) (listof string?) (listof string?) path-string? void?)]
          [write-report-cd0-cd16 (-> string? (listof natural?) string? string? (listof string?) (listof string?) path-string? void?)]
          [write-report-k1-k16 (-> string? (listof natural?) (listof string?) path-string? void?)]
          [write-report-data-start-groups (-> string? symbol? (listof string?) (listof string?) path-string? void?)]
          [write-report-des-start (-> (listof natural?) (listof natural?) (listof natural?) symbol? path-string? void?)]
          [write-report-des-data-after-padding (-> (listof string?) (listof string?) path-string? void?)]
          [write-report-des-cbc-operation (-> natural? string? string? string? path-string? void?)]
          [write-report-des-pcbc-operation (-> natural? string? string? string? string? path-string? void?)]
          [write-report-des-cofb-operation (-> string? string? string? path-string? void?)]
          [write-report-des-block-start (-> natural? string? string? path-string? void?)]
          [write-report-des-permuted (-> natural? string? string? string? string? path-string? void?)]
          [write-report-des-step (->
                                     natural?
                                     natural?
                                     string?
                                     string?
                                     string?
                                     string?
                                     string?
                                     string?
                                     string?
                                     string?
                                     path-string?
                                     void?)]
          [write-report-des-final (-> natural? string? string? path-string? void?)]
          [write-report-des-end (-> (listof string?) string? symbol? string? path-string? void?)]
          [write-report-undes-start (-> (listof natural?) (listof natural?) (listof natural?) (listof natural?) path-string? void?)]
          [write-report-undes-block-start (-> natural? string? string? path-string? void?)]
          [write-report-undes-uncipher-init (-> natural? string? string? string? string? path-string? void?)]
          [write-report-undes-cbc-operation (-> natural? string? string? string? path-string? void?)]
          [write-report-undes-pcbc-operation (-> natural? string? string? string? string? string? path-string? void?)]
          [write-report-undes-cofb-operation (-> natural? string? string? string? path-string? void?)]
          [write-report-undes-step (->
                                     natural?
                                     natural?
                                     string?
                                     string?
                                     string?
                                     string?
                                     string?
                                     string?
                                     string?
                                     string?
                                     path-string?
                                     void?)]
          [write-report-undes-final (-> natural? string? string? path-string? void?)]
          [write-report-undes-remove-padding (-> (listof string?) (listof string?) symbol? (listof string?) path-string? void?)]
          [write-report-undes-end (-> string? symbol? string? path-string? void?)]
          ))

(define (express express? proc)
  (when express?
        (proc)))



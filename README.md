ft-s3o-go
=========

[![CircleCI](https://circleci.com/gh/Financial-Times/ft-s3o-go.svg?style=svg)](https://circleci.com/gh/Financial-Times/ft-s3o-go)

Go middleware to handle authenticating with [S3O](http://s3o.ft.com/docs)

* If the user is not authenticated, the library redirects to S3O for authentication. 
* `username` and `token` cookies will be stored after a successful auth. 

For documentation, click this link:
[![GoDoc](https://godoc.org/github.com/Financial-Times/ft-s3o-go/s3o?status.svg)](https://godoc.org/github.com/Financial-Times/ft-s3o-go/s3o)

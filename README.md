# Revocation Server for NewCT Development

## Description
This server acts as a working OCSP responder for SSL Certificates with the additional benefit of revocation transparency. 
The revocation values are stored in a merkle tree and therefore inclusion and consistency proofs can be generated.

Code is written in Go 1.14, using module mode for dependencies. 

## API's
Exposed endpoints are as follows

| Endpoint                          | Request-Type | Response-Type       | Description                                                                                     |
|-----------------------------------|--------------|---------------------|-------------------------------------------------------------------------------------------------|
| /new-ct/get-sth                   | None         | types.SignedLogRoot | Signature over current Merkle Root, from the last update MMD                                    |
| /new-ct/get-inclusion-proof       | uint64       | [][]byte            | Minimum number of node hashes needed to combine with the serial leaf hash to produce the STH    |
| /new-ct/get-ocsp                  | See rfc6960  | ""                  | ""                                                                                              |
| /new-ct/post-revocation           | uint64       | None                | Accepts a serial, where its revocation value will be incorporated into the tree at the next mmd |
| /new-ct/post-multiple-revocations | []uint64     | None                | Accepts multiple serials for revocation                                                         |

Requests/Responses for all endpoints except get-ocsp are json-encoded for ease of use.
get-ocsp request/response are DER encoded and conform to RFC6960 Specification.

## Testing
Basic functionality tests for all endpoints, and ocsp tests are detailed in the testing directory

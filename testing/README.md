## Test scripts to demonstrate use/functionality of revocation server

### Basic functionality test (get-sth, get-inclusion-proof, post-revocation)
- All of these handles are json encoded request/response and therefore are human readable
- To see all options for the server, open server.go or run
- ./server --help

Steps:
1. Make sure you are at the root of the repository, so testdata/ is immediately accessible. Server has default path's it uses for the certificate and key files, and you will get an error if it cannot find those files.
2. In another terminal, start the server from root of repo `cmd/revocation-server/./server --logtostderr --v 3 --mmd "20s"`
3. Run basic_functionality.sh to see results. Output will be printed on the server side as well.

### Ocsp request/response test 

Steps:
1. Start the server the same way you did before, this time with fewer maxCerts so the proof's are more readable `cmd/revocation-server/./server --logtostderr --v 3 --mmd "20s" --max_certs 100`
2. Observe the results on both the server and client side


### Response size statistics

Here are some response sizes that I tested, with the height of the tree and corresponding maximum number of certificates storable

| Height | MaxCerts  | ResponseSize (Kb) |
|--------|------------|-------------------|
| 5      | 32         | 1.2               |
| 13     | 8192       | 1.6               |
| 20     | 1048576    | 1.9               |
| 27     | 134217728  | 2.3               |
| 30     | 1073741824 | 2.4               |

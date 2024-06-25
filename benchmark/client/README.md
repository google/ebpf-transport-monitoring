# Usage

* Build
```
go build .
```
* Run the benchmark
```
go run test --cfg ./test_input.json
```
The default location of the log files is `/tmp/h2_client_log.txt`, which can be
changed by specifying the filepath with the flag `--log`.

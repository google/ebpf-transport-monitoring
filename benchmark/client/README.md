# Usage

* Build
```
go build -o h2_client
```
* Run the benchmark
```
go run test --cfg ./test_input.json
```
## Flags
* `--cfg` specifies the path for the benchmark configuration file.
* `--log` specifies the path of the output file. The default location for the
  log files is `/tmp/h2_client_log.txt`.
  `--InsecureSkipVerify` Disables certificate verification from the client side.

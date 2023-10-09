# Lightfoot
Lightfoot is a command-line tool that can be used to track process activity on a Linux system. The tool uses eBPF technology to capture events in real-time and export them to different destinations for further analysis. Lightfoot currently tracks golang grpc http communication and correlates it with events in the underlying transport.
To use Lightfoot, you need to provide a list of process IDs (pids) that you want to trace. This can be done by passing the pids as command-line arguments. You can specify multiple pids by separating them with a space.
The following options are available for Lightfoot:
* --file_log: This option enables logging to a file instead of the standard output.
* --host_agg: This option aggregates the events at the host level instead of at the process level.
* --opencensus_log: This option enables exporting metrics and logs to Opencensus Stackdriver. The metrics will be available in Global -> Custom metrics under the path custom/opencensus/ebpf_prober. The logs will have the name ebpf_prober.

* --custom_labels: This option allows you to attach custom labels to Open Census metrics. The * labels should be specified in the format "key:value" and can be provided multiple times.
* --gcp_creds: This option allows you to specify the file path to the service account credentials for exporting to GCP.
* --gcp_project: This option allows you to specify the GCP project ID for exporting data.

Once you have specified the pids and any options, you can run Lightfoot to start tracing the processes. The tool will capture events in real-time and export them to the specified destination for further analysis.

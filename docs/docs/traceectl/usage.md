# TraceeCtl Installation and Usage Guide

## Installation

To use **TraceeCtl**, you first need to compile and install the tool. Follow these steps to get started:

### 1. **Clone the Repository**

   Begin by cloning the Tracee repository to your local machine and navigating to traceectl:

   ``` bash
   git clone https://github.com/aquasecurity/tracee.git
   cd cmd/traceectl
   ```

### 2. **Build and Install**

   Compile and install TraceeCtl using the following commands:

   ``` bash
   go build
   ```

## Configuring Tracee for TraceeCtl

To use TraceeCtl effectively, you need to configure Tracee so that it can communicate with TraceeCtl over a Unix socket. This can be done by running Tracee with the correct gRPC settings:

### 1. **Run Tracee with gRPC Unix Socket**

Use the following command to start Tracee with gRPC support over a Unix socket:

``` bash
tracee --grpc-listen-addr unix:/var/run/tracee.sock
```

This command sets up Tracee to listen for incoming connections from TraceeCtl at the specified Unix socket path (`/var/run/tracee.sock`). Ensure that this socket path is accessible and not blocked by permissions or other constraints.

### 2. **Output Flag Configuration**

The `--output` flag in Tracee allows you to configure how data from Tracee is presented. Among the available options, you can specify `none` for minimal output, which can be useful for scenarios where bandwidth or latency considerations are critical. For example:

``` bash
tracee --output none
```

#### Why Use `--output none`?

- **Reduced Bandwidth Usage:** By suppressing output, you can minimize the data transferred over the Unix socket, which is especially helpful in environments with limited resources.
- **Lower Latency:** With no data formatting or transmission overhead, the interaction between TraceeCtl and Tracee becomes faster.

Use this mode for performance testing, silent monitoring, or when integrating TraceeCtl with other systems that handle data processing separately.

This command sets up Tracee to listen for incoming connections from TraceeCtl at the specified Unix socket path (`/var/run/tracee.sock`).
Ensure that this socket path is accessible and not blocked by permissions or other constraints.

## Usage

Once TraceeCtl is installed and Tracee is running, you can use various commands to interact with Tracee. Below are the main commands provided by TraceeCtl:

- Stream Events: traceectl stream

- Events management: traceectl event

- Retrieve Metrics: traceectl metrics

- Check Version: traceectl version

For more info about the TraceeCtl command please refer to the appoint command documentation

## Flags
  
- server: Specifies the connection type, either unix or tcp.

  ``` bash
  traceectl --server unix:/unix/socket/path.sock
  ```

- output: Defines the output destination, such as stdout or a file.

  ``` bash
  traceectl stream --output file:/path/to/output.txt
  ```

For more info about the TraceeCtl flags please refer to the appoint flag documentation

## Summary

- **Install TraceeCtl** by cloning the repository, building, and installing it with `make`.
- **Configure Tracee** by running it with the appropriate gRPC Unix socket settings.
- **Use TraceeCtl** to interact with Tracee via commands like `stream`, `event`, `metrics`, and `version`.
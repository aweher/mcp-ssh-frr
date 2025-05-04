# MCP SSH Docker Server

A Message Control Protocol (MCP) server that provides SSH and Docker command execution capabilities. This server allows you to execute commands on remote systems and Docker containers through a standardized interface.

## Features

- SSH command execution on remote systems
- Docker container command execution
- Real-time command output streaming
- Progress reporting for long-running commands
- Structured JSON output support
- Command cancellation support
- Connection and command timeouts
- Comprehensive error handling

## Prerequisites

- Python 3.7+
- SSH access to target system
- Docker installed on target system (for Docker commands)

## Installation

### Using pip

```bash
pip install mcp-ssh-frr
```

### From source

1. Clone the repository:

```bash
git clone https://github.com/aweher/mcp-ssh-frr.git
cd mcp-ssh-frr
```

2. Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Install the package in development mode:

```bash
pip install -e .
```

4. Configure SSH:

   - Place your SSH private key in `./config/id_rsa`
   - Set up environment variables:

     ```bash
     export SSH_HOST="your-remote-host"
     export SSH_USER="your-username" # Defaults to root
     export SSH_PORT="22"  # Optional, defaults to 22
     ```

   - Don't forget to add your pubkey into `authorized_keys` file on `your-remote-host`

## Usage

### Starting the Server

```bash
python mcp_ssh_docker_server.py
```

### Available Tools

#### 1. SSH Command Execution (`ssh_exec`)

Execute any command on the remote system:

```python
{
    "name": "ssh_exec",
    "args": {
        "command": "ls",
        "args": ["-la", "/etc"],
        "stream": false,  # Set to true for real-time output
        "structured_output": false  # Set to true for JSON output
    }
}
```

#### 2. Docker Command Execution (`ssh_exec_docker`)

Execute commands inside Docker containers:

```python
{
    "name": "ssh_exec_docker",
    "args": {
        "container": "my-container",
        "command": "vtysh",
        "args": ["-c", "show ip bgp"],
        "stream": false,
        "structured_output": false
    }
}
```

List available containers:

```python
{
    "name": "ssh_exec_docker",
    "args": {
        "list_containers": true,
        "structured_output": false
    }
}
```

### Output Formats

1. Text Output (default):

```
$ command arg1 arg2
(exit code 0)

output line 1
output line 2
```

2. Structured JSON Output:

```json
{
    "command": "command arg1 arg2",
    "exit_code": 0,
    "stdout": "output line 1\noutput line 2",
    "stderr": "",
    "duration": 0.123,
    "metadata": {
        "container": "my-container"  // For Docker commands
    }
}
```

3. Progress Updates (when streaming):

```
[progress] 45% - Bytes read: 1024
```

## Configuration

### Timeouts

- SSH Connection Timeout: 10 seconds
- Command Execution Timeout: 30 seconds
- Stream Maximum Time: 300 seconds (5 minutes)

### Buffer Size

- Stream Buffer Size: 1024 bytes

## Error Handling

The server handles various error scenarios:

- Connection timeouts
- Authentication failures
- Command execution errors
- Docker container errors
- Command cancellation

## Security

- Uses SSH key-based authentication
- Command arguments are properly escaped
- No command injection vulnerabilities
- Secure connection handling

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

GPLv3

## Author

Ariel S. Weher <ariel[at]weher.net>

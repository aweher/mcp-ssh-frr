# MCP SSH Docker Server - AI Usage Guide

## Overview

This tool provides remote command execution capabilities via SSH, with special support for Docker container operations. It exposes two main tools: `ssh_exec` and `ssh_exec_docker`.

## Prerequisites

1. Environment Variables Required:
   - `SSH_HOST`: Target host address
   - `SSH_USER`: SSH username (defaults to 'root')
   - `SSH_PORT`: SSH port (defaults to 22)
2. SSH Key:
   - Private key must be present at `./config/id_rsa`

## Request Structure

All requests must follow this structure:

```json
{
    "name": "tool_name",
    "args": {
        // tool-specific arguments
    }
}
```

### Common Errors

1. Missing request structure:
```json
// Incorrect
{
    "list_containers": true
}

// Correct
{
    "name": "ssh_exec_docker",
    "args": {
        "list_containers": true
    }
}
```

2. Missing required fields:
```json
// Incorrect
{
    "name": "ssh_exec_docker",
    "args": {
        "command": "ls"
    }
}

// Correct
{
    "name": "ssh_exec_docker",
    "args": {
        "container": "my-container",
        "command": "ls"
    }
}
```

## Available Tools

### 1. ssh_exec

Purpose: Execute commands directly on the remote system via SSH.

#### Parameters:

- `command` (required): The command to execute
- `args` (optional): Array of command arguments
- `stream` (optional): Boolean to enable real-time output streaming
- `structured_output` (optional): Boolean to return JSON-formatted results

#### Example Usage:

```json
# Basic command execution
{
    "name": "ssh_exec",
    "args": {
        "command": "ls",
        "args": ["-la", "/home"]
    }
}

# Streaming output
{
    "name": "ssh_exec",
    "args": {
        "command": "tail",
        "args": ["-f", "/var/log/syslog"],
        "stream": true
    }
}

# Structured output
{
    "name": "ssh_exec",
    "args": {
        "command": "df",
        "args": ["-h"],
        "structured_output": true
    }
}
```

### 2. ssh_exec_docker

Purpose: Execute commands inside Docker containers on the remote system.

#### Parameters:

- `command` (required): The command to execute inside the container
- `container` (required): Name of the target container
- `args` (optional): Array of command arguments
- `stream` (optional): Boolean to enable real-time output streaming
- `structured_output` (optional): Boolean to return JSON-formatted results
- `list_containers` (optional): Boolean to list available containers

#### Example Usage:

```json
# List available containers
{
    "name": "ssh_exec_docker",
    "args": {
        "list_containers": true
    }
}

# Execute command in container
{
    "name": "ssh_exec_docker",
    "args": {
        "container": "my-container",
        "command": "ps",
        "args": ["aux"]
    }
}

# Stream container command output
{
    "name": "ssh_exec_docker",
    "args": {
        "container": "my-container",
        "command": "tail",
        "args": ["-f", "/var/log/app.log"],
        "stream": true
    }
}
```

## Response Types

The tool returns different content types:

1. `TextContent`:

```json
{
    "type": "text",
    "text": "command output here"
}
```

2. `ProgressContent` (for streaming):

```json
{
    "type": "progress",
    "progress": 50,
    "message": "Bytes read: 1024"
}
```

3. `JsonContent` (for structured output):

```json
{
    "type": "json",
    "data": {
        "command": "executed command",
        "exit_code": 0,
        "stdout": "output",
        "stderr": "errors",
        "duration": 1.23,
        "metadata": {}
    }
}
```

4. `ErrorContent`:

```json
{
    "type": "text",
    "text": "Error: [error message]"
}
```

## Error Messages

The server provides clear error messages for common issues:

1. Invalid request structure:
   - "Error: 'args' debe ser un objeto/diccionario"
   - "Error: Herramienta no soportada: [tool_name]"

2. Missing required fields:
   - "Error: Command field is required"
   - "Error: Both 'container' and 'command' fields are required"
   - "Error: Se requieren los campos 'commands' y 'container'"

3. Invalid input:
   - "Error: Invalid command input: [details]"
   - "Error: Todos los comandos deben ser strings"

4. Execution errors:
   - "Error: SSH Error: [details]"
   - "Error: Command cancelled: [details]"
   - "Error: Error listing containers: [details]"

## Important Limitations

1. Timeouts:
   - SSH Connection: 10 seconds
   - Command Execution: 30 seconds
   - Stream Maximum Time: 300 seconds (5 minutes)

2. Buffer Size:
   - Stream buffer size: 1024 bytes

3. Error Handling:
   - SSH connection failures
   - Authentication errors
   - Command execution timeouts
   - Network errors
   - Command cancellation

## Best Practices

1. Always check for command completion and exit codes
2. Use streaming for long-running commands
3. Handle both stdout and stderr outputs
4. Use structured output for programmatic processing
5. Implement proper error handling for SSH and command execution failures
6. Close SSH connections after use (handled automatically by the tool)
7. Always use the correct request structure with `name` and `args` fields
8. Validate all required fields before sending requests

## Security Considerations

1. Use environment variables for sensitive connection details
2. Avoid sending sensitive data as command arguments
3. Implement proper access controls on the SSH private key
4. Monitor and log command executions
5. Use specific container names rather than IDs for clarity and security

## Error Handling Examples

### Request Structure Errors

```json
// Incorrect request
{
    "list_containers": true
}

// Error response
{
    "type": "text",
    "text": "Error: 'args' debe ser un objeto/diccionario"
}
```

### Missing Required Fields

```json
// Incorrect request
{
    "name": "ssh_exec_docker",
    "args": {
        "command": "ls"
    }
}

// Error response
{
    "type": "text",
    "text": "Error: Both 'container' and 'command' fields are required"
}
```

### SSH Connection Errors

```json
// Error response
{
    "type": "text",
    "text": "Error: SSH Error: Connection timed out after 10 seconds"
}
```

## Common Use Cases

1. **System Monitoring**

```json
{
    "name": "ssh_exec",
    "args": {
        "command": "top",
        "args": ["-b", "-n", "1"],
        "structured_output": true
    }
}
```

2. **Container Management**

```json
{
    "name": "ssh_exec_docker",
    "args": {
        "command": "docker",
        "args": ["stats", "--no-stream"],
        "structured_output": true
    }
}
```

3. **Log Monitoring**

```json
{
    "name": "ssh_exec_docker",
    "args": {
        "container": "app-container",
        "command": "tail",
        "args": ["-f", "/var/log/app.log"],
        "stream": true
    }
}
```

4. **Get Router RIB**

```json
{
    "name": "ssh_exec_docker",
    "args": {
        "container": "mpls-p2",
        "command": "vtysh",
        "args": ["-c", "show ip route"]
    }
}
```

## Troubleshooting Guide

1. **Request Structure Issues**
   - Verify request has both `name` and `args` fields
   - Check that `args` is an object/dictionary
   - Ensure all required fields are present

2. **Connection Issues**
   - Verify SSH_HOST and SSH_USER environment variables
   - Check SSH key permissions
   - Ensure network connectivity to target host

3. **Command Execution Issues**
   - Verify command syntax
   - Check user permissions
   - Review command timeout settings

4. **Container Issues**
   - Verify container exists and is running
   - Check container permissions
   - Review Docker daemon status

## Performance Optimization

1. Use streaming for long-running commands
2. Implement proper timeout handling
3. Close connections when not in use
4. Use structured output for better parsing
5. Implement proper error handling and retries

## Version Information

- Tool Version: 1.0.0
- Supported Features: SSH execution, Docker container execution, streaming output, structured output
- Author: Ariel S. Weher

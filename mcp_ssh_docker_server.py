import asyncio
import io
import logging
import os
import shlex
import socket
import sys
from typing import Tuple, AsyncGenerator, Dict, Any, Union, Optional

import paramiko
from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.stdio import stdio_server
from pydantic import BaseModel, Field, field_validator

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("docker_mcp_server")

# Version and metadata
VERSION = "1.0.0"
TOOL_METADATA = {
    "name": "docker_mcp_server",
    "version": VERSION,
    "description": "SSH and Docker command execution server",
    "author": "Ariel S. Weher",
    "capabilities": ["ssh_exec", "docker_exec"]
}

# Connection settings
SSH_TIMEOUT = 10  # seconds
COMMAND_TIMEOUT = 30  # seconds
STREAM_BUFFER_SIZE = 1024  # bytes
STREAM_MAX_TIME = 300  # 5 minutes maximum for streaming commands
MAX_OUTPUT_SIZE = 1024 * 1024  # 1MB maximum output size

# Fixed private key path
PRIVATE_KEY_PATH = "./config/id_rsa"

# Initialize MCP server
app = Server("docker_mcp_server")

class ProgressContent(BaseModel):
    """Content type for progress updates"""
    type: str = "progress"
    progress: int
    message: str

    @field_validator('progress')
    @classmethod
    def validate_progress(cls, v: int) -> int:
        if not 0 <= v <= 100:
            raise ValueError('Progress must be between 0 and 100')
        return v

class JsonContent(BaseModel):
    """Content type for structured JSON output"""
    type: str = "json"
    data: Dict[str, Any]

class CommandResult(BaseModel):
    """Structured output for command results"""
    command: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator('exit_code')
    @classmethod
    def validate_exit_code(cls, v: int) -> int:
        if v < 0:
            raise ValueError('Exit code cannot be negative')
        return v

    @field_validator('duration')
    @classmethod
    def validate_duration(cls, v: float) -> float:
        if v < 0:
            raise ValueError('Duration cannot be negative')
        return v

class SSHError(Exception):
    """Custom exception for SSH-related errors"""
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        super().__init__(message)
        self.original_error = original_error

class CommandCancelled(Exception):
    """Exception raised when a command is cancelled"""
    pass

# Type alias for all possible content types
ContentType = Union[TextContent, ProgressContent, JsonContent]

def validate_command_input(cmd: str, args: list) -> None:
    """Validates command and arguments for security and correctness"""
    if not cmd or not isinstance(cmd, str):
        raise ValueError("Invalid command")
    if not isinstance(args, list):
        raise ValueError("Args must be a list")
    for arg in args:
        if not isinstance(arg, str):
            raise ValueError("All args must be strings")
        # Basic command injection prevention
        if any(char in arg for char in [';', '|', '&', '>', '<', '`', '$']):
            raise ValueError("Invalid characters in command arguments")

def ssh_connect() -> paramiko.SSHClient:
    """Returns an SSH session ready to use, using SSH_* environment variables"""
    ssh_host = os.getenv("SSH_HOST")
    ssh_user = os.getenv("SSH_USER", 'root')
    ssh_port = int(os.getenv("SSH_PORT", "22"))

    if not ssh_host or not ssh_user:
        raise SSHError("Missing SSH_HOST or SSH_USER environment variables")

    logger.info(f"Connecting to {ssh_user}@{ssh_host}:{ssh_port}")

    try:
        # Load private key
        try:
            with open(PRIVATE_KEY_PATH, "r", encoding="utf-8") as key_file:
                private_key = key_file.read()
        except (FileNotFoundError, PermissionError) as e:
            raise SSHError(f"Failed to read SSH key: {str(e)}", original_error=e)

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        pkey = paramiko.RSAKey.from_private_key(io.StringIO(private_key))
            
        ssh.connect(
            hostname=ssh_host,
            port=ssh_port,
            username=ssh_user,
            pkey=pkey,
            timeout=SSH_TIMEOUT,
            banner_timeout=SSH_TIMEOUT,
            auth_timeout=SSH_TIMEOUT
        )
        return ssh
    except paramiko.AuthenticationException as exc:
        raise SSHError("Authentication failed. Check your SSH credentials.", original_error=exc)
    except paramiko.SSHException as e:
        raise SSHError(f"SSH error: {str(e)}", original_error=e)
    except socket.timeout as exc:
        raise SSHError(f"Connection timed out after {SSH_TIMEOUT} seconds", original_error=exc)
    except socket.error as e:
        raise SSHError(f"Network error: {str(e)}", original_error=e)
    except Exception as e:
        raise SSHError(f"Unexpected error: {str(e)}", original_error=e)

async def stream_ssh_command(
    ssh: paramiko.SSHClient, 
    command: str,
    progress_callback=None,
    cancellation_event=None
) -> AsyncGenerator[ContentType, None]:
    """Execute a command via SSH and stream its output"""
    stdin = stdout = stderr = None
    try:
        stdin, stdout, stderr = ssh.exec_command(command, timeout=COMMAND_TIMEOUT)
        start_time = asyncio.get_event_loop().time()
        bytes_read = 0
        
        # Stream stdout
        while True:
            # Check for cancellation
            if cancellation_event and cancellation_event.is_set():
                raise CommandCancelled("Command was cancelled by user")
                
            # Check if we've exceeded the maximum time
            if asyncio.get_event_loop().time() - start_time > STREAM_MAX_TIME:
                yield TextContent(type="text", text=f"\n[Stream timeout after {STREAM_MAX_TIME} seconds]")
                break
                
            try:
                line = stdout.readline(timeout=1.0)  # 1 second timeout for readline
                if not line:
                    break
                    
                bytes_read += len(line)
                if progress_callback:
                    yield ProgressContent(
                        type="progress",
                        progress=min(100, int((bytes_read / STREAM_BUFFER_SIZE) * 100)),
                        message=f"Bytes read: {bytes_read}"
                    )
                    
                yield TextContent(type="text", text=line)
            except socket.timeout:
                continue  # Retry readline
        
        # Stream stderr
        while True:
            if cancellation_event and cancellation_event.is_set():
                raise CommandCancelled("Command was cancelled by user")
                
            if asyncio.get_event_loop().time() - start_time > STREAM_MAX_TIME:
                yield TextContent(type="text", text=f"\n[Stream timeout after {STREAM_MAX_TIME} seconds]")
                break
                
            try:
                line = stderr.readline(timeout=1.0)  # 1 second timeout for readline
                if not line:
                    break
                    
                yield TextContent(type="text", text=f"[stderr] {line}")
            except socket.timeout:
                continue  # Retry readline
        
        exit_code = stdout.channel.recv_exit_status()
        duration = asyncio.get_event_loop().time() - start_time
        
        # Send structured result
        result = CommandResult(
            command=command,
            exit_code=exit_code,
            duration=duration,
            metadata={"bytes_read": bytes_read}
        )
        yield JsonContent(type="json", data=result.model_dump())
        
    except socket.timeout as exc:
        raise SSHError(f"Command execution timed out after {COMMAND_TIMEOUT} seconds", original_error=exc)
    except Exception as e:
        raise SSHError(f"Command execution failed: {str(e)}", original_error=e)
    finally:
        # Clean up resources
        for stream in (stdin, stdout, stderr):
            if stream:
                try:
                    stream.close()
                except Exception:
                    pass

def execute_ssh_command(ssh: paramiko.SSHClient, command: str) -> Tuple[str, str, int]:
    """Execute a command via SSH with timeout and return (stdout, stderr, exit_code)"""
    stdin = stdout = stderr = None
    try:
        stdin, stdout, stderr = ssh.exec_command(command, timeout=COMMAND_TIMEOUT)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read(MAX_OUTPUT_SIZE).decode()
        err = stderr.read(MAX_OUTPUT_SIZE).decode()
        return out, err, exit_code
    except socket.timeout as exc:
        raise SSHError(f"Command execution timed out after {COMMAND_TIMEOUT} seconds", original_error=exc)
    except Exception as e:
        raise SSHError(f"Command execution failed: {str(e)}", original_error=e)
    finally:
        # Clean up resources
        for stream in (stdin, stdout, stderr):
            if stream:
                try:
                    stream.close()
                except Exception:
                    pass

def list_containers() -> list[str]:
    """Lists running Docker containers using docker ps"""
    ssh = None
    try:
        ssh = ssh_connect()
        out, err, exit_code = execute_ssh_command(ssh, 'docker ps --format "{{.Names}}"')
        if exit_code != 0:
            raise SSHError(f"Failed to list containers: {err}")
        return [c for c in out.strip().split('\n') if c]
    finally:
        if ssh:
            ssh.close()

@app.list_tools()
async def list_tools() -> list[Tool]:
    """Returns a list of available tools with their metadata and input schemas."""
    return [
        Tool(
            name="ssh_exec_docker",
            description="Executes a command inside a remote container via docker exec and SSH",
            version=VERSION,
            metadata=TOOL_METADATA,
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Command to execute (e.g: vtysh)"},
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Command arguments"
                    },
                    "container": {
                        "type": "string",
                        "description": "Container name where to execute the command"
                    },
                    "list_containers": {
                        "type": "boolean",
                        "description": "If true, lists available containers instead of executing a command"
                    },
                    "stream": {
                        "type": "boolean",
                        "description": "If true, streams command output in real-time"
                    },
                    "structured_output": {
                        "type": "boolean",
                        "description": "If true, returns output in structured JSON format"
                    }
                },
                "required": ["command"]
            }
        ),
        Tool(
            name="ssh_exec",
            description="Executes any command on the remote system via SSH",
            version=VERSION,
            metadata=TOOL_METADATA,
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Command to execute"},
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Command arguments"
                    },
                    "stream": {
                        "type": "boolean",
                        "description": "If true, streams command output in real-time"
                    },
                    "structured_output": {
                        "type": "boolean",
                        "description": "If true, returns output in structured JSON format"
                    }
                },
                "required": ["command"]
            }
        ),
        Tool(
            name="ssh_exec_vtysh",
            description="Ejecuta comandos vtysh en un contenedor FRR remoto vía SSH y docker exec",
            version=VERSION,
            metadata=TOOL_METADATA,
            inputSchema={
                "type": "object",
                "properties": {
                    "commands": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Lista de comandos vtysh a ejecutar (se ejecutan en orden)"
                    },
                    "container": {
                        "type": "string",
                        "description": "Nombre del contenedor FRR"
                    },
                    "stream": {
                        "type": "boolean",
                        "description": "Si es true, streamea la salida en tiempo real"
                    },
                    "structured_output": {
                        "type": "boolean",
                        "description": "Si es true, retorna la salida en formato JSON estructurado"
                    }
                },
                "required": ["commands", "container"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, args: dict) -> AsyncGenerator[ContentType, None]:
    """Executes the specified tool with given arguments and yields content as it becomes available."""
    if name not in ["ssh_exec", "ssh_exec_docker", "ssh_exec_vtysh"]:
        yield TextContent(type="text", text=f"Unsupported tool: {name}")
        return

    ssh = None
    cancellation_event = asyncio.Event()
    
    try:
        if name == "ssh_exec_vtysh":
            commands = args.get("commands", [])
            container = args.get("container")
            stream = args.get("stream", False)
            structured_output = args.get("structured_output", False)

            if not commands or not container:
                yield TextContent(type="text", text="Se requieren los campos 'commands' y 'container'")
                return

            # Validación básica
            for cmd in commands:
                if not isinstance(cmd, str):
                    yield TextContent(type="text", text="Todos los comandos deben ser strings")
                    return

            ssh = ssh_connect()
            # Construir el comando vtysh
            # Si es un solo comando, usar -c; si son varios, usar -b y pasar un script
            if len(commands) == 1:
                vtysh_cmd = f"vtysh -c {shlex.quote(commands[0])}"
            else:
                # Crear un script temporal y ejecutarlo con vtysh -b
                script = "\n".join(commands)
                # Usar echo + pipe para pasar los comandos a vtysh
                vtysh_cmd = f"echo {shlex.quote(script)} | vtysh -b"

            final_command = f'docker exec -i {container} bash -c {shlex.quote(vtysh_cmd)}'
            logger.info(f"Executing: {final_command}")

            if stream:
                yield TextContent(type="text", text=f"$ {final_command}\n")
                async for output in stream_ssh_command(
                    ssh, 
                    final_command,
                    progress_callback=True,
                    cancellation_event=cancellation_event
                ):
                    yield output
                return

            out, err, exit_code = execute_ssh_command(ssh, final_command)
            
            if structured_output:
                result = CommandResult(
                    command=final_command,
                    exit_code=exit_code,
                    stdout=out,
                    stderr=err,
                    metadata={"container": container, "vtysh_commands": commands}
                )
                yield JsonContent(type="json", data=result.model_dump())
                return
            
            result = f"$ {final_command}\n"
            result += f"(exit code {exit_code})\n\n"
            result += out or ""
            if err:
                result += f"\n[stderr]\n{err}"
            yield TextContent(type="text", text=result)
            return

        if name == "ssh_exec":
            cmd = args.get("command")
            cmd_args = args.get("args", [])
            stream = args.get("stream", False)
            structured_output = args.get("structured_output", False)

            try:
                validate_command_input(cmd, cmd_args)
            except ValueError as e:
                yield TextContent(type="text", text=f"Invalid command input: {str(e)}")
                return

            if not cmd:
                yield TextContent(type="text", text="Command field is required")
                return

            ssh = ssh_connect()
            args_quoted = " ".join(shlex.quote(arg) for arg in cmd_args)
            final_command = f"{cmd} {args_quoted}"
            logger.info(f"Executing: {final_command}")

            if stream:
                yield TextContent(type="text", text=f"$ {final_command}\n")
                async for output in stream_ssh_command(
                    ssh, 
                    final_command,
                    progress_callback=True,
                    cancellation_event=cancellation_event
                ):
                    yield output
                return

            out, err, exit_code = execute_ssh_command(ssh, final_command)
            
            if structured_output:
                result = CommandResult(
                    command=final_command,
                    exit_code=exit_code,
                    stdout=out,
                    stderr=err
                )
                yield JsonContent(type="json", data=result.model_dump())
                return
            
            result = f"$ {final_command}\n"
            result += f"(exit code {exit_code})\n\n"
            result += out or ""
            if err:
                result += f"\n[stderr]\n{err}"
            yield TextContent(type="text", text=result)
            return

        # ssh_exec_docker logic
        list_containers_flag = args.get("list_containers", False)
        if list_containers_flag:
            try:
                containers = list_containers()
                if args.get("structured_output", False):
                    yield JsonContent(type="json", data={"containers": containers})
                else:
                    yield TextContent(type="text", text="Available containers:\n" + "\n".join(containers))
                return
            except SSHError as e:
                yield TextContent(type="text", text=f"Error listing containers: {str(e)}")
                return

        container = args.get("container")
        cmd = args.get("command")
        cmd_args = args.get("args", [])
        stream = args.get("stream", False)
        structured_output = args.get("structured_output", False)

        try:
            validate_command_input(cmd, cmd_args)
        except ValueError as e:
            yield TextContent(type="text", text=f"Invalid command input: {str(e)}")
            return

        if not all([container, cmd]):
            yield TextContent(type="text", text="Both 'container' and 'command' fields are required")
            return

        ssh = ssh_connect()
        args_quoted = " ".join(shlex.quote(arg) for arg in cmd_args)
        final_command = f'docker exec -i {container} {cmd} {args_quoted}'
        logger.info(f"Executing: {final_command}")

        if stream:
            yield TextContent(type="text", text=f"$ {final_command}\n")
            async for output in stream_ssh_command(
                ssh, 
                final_command,
                progress_callback=True,
                cancellation_event=cancellation_event
            ):
                yield output
            return

        out, err, exit_code = execute_ssh_command(ssh, final_command)
        
        if structured_output:
            result = CommandResult(
                command=final_command,
                exit_code=exit_code,
                stdout=out,
                stderr=err,
                metadata={"container": container}
            )
            yield JsonContent(type="json", data=result.model_dump())
            return
        
        result = f"$ {final_command}\n"
        result += f"(exit code {exit_code})\n\n"
        result += out or ""
        if err:
            result += f"\n[stderr]\n{err}"
        yield TextContent(type="text", text=result)
        return

    except CommandCancelled as e:
        yield TextContent(type="text", text=f"Command cancelled: {str(e)}")
    except SSHError as e:
        yield TextContent(type="text", text=f"SSH Error: {str(e)}")
    except Exception as e:
        yield TextContent(type="text", text=f"Error: {str(e)}")
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass  # Ignore errors during cleanup

async def main():
    """Initializes and runs the MCP server using stdio for communication."""
    print("Starting docker MCP server...", file=sys.stderr)
    async with stdio_server() as (reader, writer):
        await app.run(reader, writer, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())

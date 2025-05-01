import asyncio
import logging
import os
import sys
import io
import paramiko
import shlex
from mcp.server import Server
from mcp.types import Tool, TextContent
from mcp.server.stdio import stdio_server
from pydantic import BaseModel

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("docker_mcp_server")

# Fixed private key
PRIVATE_KEY_PATH = "./config/id_rsa"

with open(PRIVATE_KEY_PATH, "r") as key_file:
    PRIVATE_KEY = key_file.read()

# Initialize MCP server
app = Server("docker_mcp_server")

def ssh_connect():
    """Returns an SSH session ready to use, using SSH_* environment variables"""
    ssh_host = os.getenv("SSH_HOST")
    ssh_user = os.getenv("SSH_USER", 'root')
    ssh_port = int(os.getenv("SSH_PORT", "22"))

    if not ssh_host or not ssh_user:
        raise ValueError("Missing SSH_HOST or SSH_USER environment variables")

    logger.info(f"Connecting to {ssh_user}@{ssh_host}:{ssh_port}")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = paramiko.RSAKey.from_private_key(io.StringIO(PRIVATE_KEY))
    ssh.connect(hostname=ssh_host, port=ssh_port, username=ssh_user, pkey=pkey)
    return ssh

def list_containers() -> list[str]:
    """Lists running Docker containers using docker ps"""
    ssh = ssh_connect()
    stdin, stdout, stderr = ssh.exec_command('docker ps --format "{{.Names}}"')
    containers = stdout.read().decode().strip().split('\n')
    ssh.close()
    return [c for c in containers if c]  # Filter empty lines

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="ssh_exec_docker",
            description="Executes a command inside a remote container via docker exec and SSH",
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
                    }
                },
                "required": ["command"]
            }
        ),
        Tool(
            name="ssh_exec",
            description="Executes any command on the remote system via SSH",
            inputSchema={
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Command to execute"},
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Command arguments"
                    }
                },
                "required": ["command"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, args: dict) -> list[TextContent]:
    if name not in ["ssh_exec", "ssh_exec_docker"]:
        raise ValueError(f"Unsupported tool: {name}")

    if name == "ssh_exec":
        cmd = args.get("command")
        cmd_args = args.get("args", [])

        if not cmd:
            raise ValueError("Command field is required")

        ssh = ssh_connect()
        args_quoted = " ".join(shlex.quote(arg) for arg in cmd_args)
        final_command = f"{cmd} {args_quoted}"
        logger.info(f"Executing: {final_command}")

        stdin, stdout, stderr = ssh.exec_command(final_command)
        out = stdout.read().decode()
        err = stderr.read().decode()
        exit_code = stdout.channel.recv_exit_status()
        ssh.close()

        result = f"$ {final_command}\n"
        result += f"(exit code {exit_code})\n\n"
        result += out or ""
        if err:
            result += f"\n[stderr]\n{err}"

        return [TextContent(type="text", text=result)]

    # ssh_exec_docker logic
    list_containers = args.get("list_containers", False)
    if list_containers:
        containers = list_containers()
        return [TextContent(type="text", text="Available containers:\n" + "\n".join(containers))]

    container = args.get("container")
    cmd = args.get("command")
    cmd_args = args.get("args", [])

    if not all([container, cmd]):
        raise ValueError("Both 'container' and 'command' fields are required")

    ssh = ssh_connect()

    args_quoted = " ".join(shlex.quote(arg) for arg in cmd_args)
    final_command = f'docker exec -i {container} {cmd} {args_quoted}'
    logger.info(f"Executing: {final_command}")

    stdin, stdout, stderr = ssh.exec_command(final_command)
    out = stdout.read().decode()
    err = stderr.read().decode()
    exit_code = stdout.channel.recv_exit_status()

    ssh.close()

    result = f"$ docker exec -i {container} {cmd} {' '.join(cmd_args)}\n"
    result += f"(exit code {exit_code})\n\n"
    result += out or ""
    if err:
        result += f"\n[stderr]\n{err}"

    return [TextContent(type="text", text=result)]

async def main():
    print("Starting docker MCP server...", file=sys.stderr)
    async with stdio_server() as (reader, writer):
        await app.run(reader, writer, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
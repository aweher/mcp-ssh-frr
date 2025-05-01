import pytest
import asyncio
import socket
from unittest.mock import Mock, patch, AsyncMock
import paramiko
from mcp_ssh_docker_server import (
    ssh_connect,
    execute_ssh_command,
    list_containers,
    stream_ssh_command,
    SSHError,
    CommandCancelled,
    CommandResult,
    ContentType,
    TextContent,
    JsonContent,
    ProgressContent,
    call_tool
)

# Test data
MOCK_SSH_HOST = "test-host"
MOCK_SSH_USER = "test-user"
MOCK_SSH_PORT = 22
MOCK_PRIVATE_KEY = "test-key"
MOCK_CONTAINER = "test-container"
MOCK_COMMAND = "test-command"
MOCK_ARGS = ["arg1", "arg2"]

@pytest.fixture
def mock_env_vars(monkeypatch):
    """Set up mock environment variables for SSH connection."""
    monkeypatch.setenv("SSH_HOST", MOCK_SSH_HOST)
    monkeypatch.setenv("SSH_USER", MOCK_SSH_USER)
    monkeypatch.setenv("SSH_PORT", str(MOCK_SSH_PORT))

@pytest.fixture
def mock_ssh_client():
    """Create a mock SSH client."""
    mock_client = Mock(spec=paramiko.SSHClient)
    mock_client.connect = Mock()
    return mock_client

@pytest.fixture
def mock_ssh_channel():
    """Create a mock SSH channel."""
    mock_channel = Mock()
    mock_channel.recv_exit_status.return_value = 0
    return mock_channel

@pytest.fixture
def mock_stdout(mock_ssh_channel):
    """Create a mock stdout."""
    mock_stdout = Mock()
    mock_stdout.channel = mock_ssh_channel
    mock_stdout.readline = Mock(return_value="test output\n")
    mock_stdout.read = Mock(return_value=b"test output")
    return mock_stdout

@pytest.fixture
def mock_stderr():
    """Create a mock stderr."""
    mock_stderr = Mock()
    mock_stderr.read = Mock(return_value=b"")
    return mock_stderr

def test_ssh_connect_success(mock_env_vars, mock_ssh_client):
    """Test successful SSH connection."""
    with patch('paramiko.SSHClient', return_value=mock_ssh_client), \
         patch('paramiko.RSAKey.from_private_key'):
        ssh = ssh_connect()
        assert ssh == mock_ssh_client
        mock_ssh_client.connect.assert_called_once()

def test_ssh_connect_missing_env_vars():
    """Test SSH connection with missing environment variables."""
    with pytest.raises(SSHError, match="Missing SSH_HOST or SSH_USER"):
        ssh_connect()

def test_ssh_connect_auth_failure(mock_env_vars, mock_ssh_client):
    """Test SSH connection with authentication failure."""
    mock_ssh_client.connect.side_effect = paramiko.AuthenticationException()
    with patch('paramiko.SSHClient', return_value=mock_ssh_client), \
         patch('paramiko.RSAKey.from_private_key'):
        with pytest.raises(SSHError, match="Authentication failed"):
            ssh_connect()

def test_execute_ssh_command_success(mock_ssh_client, mock_stdout, mock_stderr):
    """Test successful command execution."""
    mock_ssh_client.exec_command.return_value = (None, mock_stdout, mock_stderr)
    out, err, exit_code = execute_ssh_command(mock_ssh_client, MOCK_COMMAND)
    assert out == "test output"
    assert err == ""
    assert exit_code == 0

def test_execute_ssh_command_timeout(mock_ssh_client):
    """Test command execution timeout."""
    mock_ssh_client.exec_command.side_effect = socket.timeout()
    with pytest.raises(SSHError, match="Command execution timed out"):
        execute_ssh_command(mock_ssh_client, MOCK_COMMAND)

@pytest.mark.asyncio
async def test_stream_ssh_command_success(mock_ssh_client, mock_stdout, mock_stderr):
    """Test successful command streaming."""
    mock_ssh_client.exec_command.return_value = (None, mock_stdout, mock_stderr)
    async for content in stream_ssh_command(mock_ssh_client, MOCK_COMMAND):
        assert isinstance(content, (TextContent, JsonContent, ProgressContent))

@pytest.mark.asyncio
async def test_stream_ssh_command_cancellation(mock_ssh_client, mock_stdout, mock_stderr):
    """Test command streaming cancellation."""
    mock_ssh_client.exec_command.return_value = (None, mock_stdout, mock_stderr)
    cancellation_event = asyncio.Event()
    cancellation_event.set()
    
    with pytest.raises(CommandCancelled):
        async for _ in stream_ssh_command(
            mock_ssh_client, 
            MOCK_COMMAND,
            cancellation_event=cancellation_event
        ):
            pass

def test_list_containers_success(mock_ssh_client, mock_stdout, mock_stderr):
    """Test successful container listing."""
    mock_stdout.read.return_value = b"container1\ncontainer2\n"
    mock_ssh_client.exec_command.return_value = (None, mock_stdout, mock_stderr)
    
    with patch('mcp_ssh_docker_server.ssh_connect', return_value=mock_ssh_client):
        containers = list_containers()
        assert containers == ["container1", "container2"]

def test_list_containers_failure(mock_ssh_client, mock_stdout, mock_stderr):
    """Test container listing failure."""
    mock_stderr.read.return_value = b"Error listing containers"
    mock_ssh_client.exec_command.return_value = (None, mock_stdout, mock_stderr)
    mock_stdout.channel.recv_exit_status.return_value = 1
    
    with patch('mcp_ssh_docker_server.ssh_connect', return_value=mock_ssh_client):
        with pytest.raises(SSHError, match="Failed to list containers"):
            list_containers()

@pytest.mark.asyncio
async def test_call_tool_unsupported():
    """Test calling an unsupported tool."""
    async for content in call_tool("unsupported_tool", {}):
        assert isinstance(content, TextContent)
        assert "Unsupported tool" in content.text

@pytest.mark.asyncio
async def test_call_tool_ssh_exec(mock_ssh_client, mock_stdout, mock_stderr):
    """Test SSH command execution through call_tool."""
    mock_stdout.read.return_value = b"command output"
    mock_ssh_client.exec_command.return_value = (None, mock_stdout, mock_stderr)
    
    with patch('mcp_ssh_docker_server.ssh_connect', return_value=mock_ssh_client):
        async for content in call_tool("ssh_exec", {
            "command": MOCK_COMMAND,
            "args": MOCK_ARGS
        }):
            assert isinstance(content, TextContent)
            assert MOCK_COMMAND in content.text

@pytest.mark.asyncio
async def test_call_tool_ssh_exec_docker(mock_ssh_client, mock_stdout, mock_stderr):
    """Test Docker command execution through call_tool."""
    mock_stdout.read.return_value = b"docker command output"
    mock_ssh_client.exec_command.return_value = (None, mock_stdout, mock_stderr)
    
    with patch('mcp_ssh_docker_server.ssh_connect', return_value=mock_ssh_client):
        async for content in call_tool("ssh_exec_docker", {
            "container": MOCK_CONTAINER,
            "command": MOCK_COMMAND,
            "args": MOCK_ARGS
        }):
            assert isinstance(content, TextContent)
            assert MOCK_CONTAINER in content.text
            assert MOCK_COMMAND in content.text 
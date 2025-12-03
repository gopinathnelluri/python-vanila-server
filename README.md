# Vanilla Python File API Server

A single-file, dependency-free Python HTTP server for serving files and metadata with security scopes, daemon support, and auto-stop capabilities.

## Features

- **Zero Dependencies**: Runs with standard Python 3 libraries.
- **Scope Restriction**: Restrict access to specific directories.
- **Metadata Support**: Retrieve file metadata (owner, permissions, size) as JSON.
- **Large File Support**: Efficient streaming for large files.
- **Daemon Mode**: Run in background with PID file management.
- **Auto-Stop**: Automatically shut down after a specified timeout.
- **JSON Errors**: Returns structured JSON error responses.

## Usage

```bash
python3 file_server.py [OPTIONS]
```

### Options

| Option | Description | Default |
| :--- | :--- | :--- |
| `--port PORT` | Port to run the server on. | `7200` |
| `--scope [PATH ...]` | List of allowed directory scopes. If omitted, allows ALL paths. | `None` (All) |
| `--daemon` | Run as a background daemon process. | `False` |
| `--stop` | Stop the running daemon (requires `--pid-file`). | `False` |
| `--pid-file PATH` | Path to the PID file. | `file_server.pid` |
| `--timeout SECONDS` | Auto-stop the server after N seconds. | `None` |

## Examples

### 1. Basic Usage
Serve files from the current directory on port 7200:
```bash
python3 file_server.py
```

### 2. Restricted Scope
Only allow access to `/var/log` and `/tmp`:
```bash
python3 file_server.py --scope /var/log /tmp
```

### 3. Daemon Mode
Start the server in the background:
```bash
python3 file_server.py --daemon --pid-file /tmp/server.pid
```

Stop the server:
```bash
python3 file_server.py --stop --pid-file /tmp/server.pid
```

### 4. Auto-Stop Timeout
Run the server and automatically exit after 60 seconds (useful for temporary access):
```bash
python3 file_server.py --timeout 60
```

## API Endpoints

### Get File Content
**GET** `/?path=/path/to/file`

Returns the raw file content.

### Get File Metadata
**GET** `/?path=/path/to/file&mode=metadata`

Returns JSON metadata:
```json
{
  "path": "/path/to/file",
  "size": 1024,
  "owner": "user",
  "group": "staff",
  "permissions": "644",
  "uid": 501,
  "gid": 20,
  "atime": 1700000000.0,
  "mtime": 1700000000.0,
  "ctime": 1700000000.0
}
```

### Error Responses
Errors are returned as JSON:
```json
{
  "error": true,
  "code": 404,
  "message": "File not found",
  "details": "Nothing matches the given URI"
}
```

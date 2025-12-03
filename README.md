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
**GET** `/?file-path=/path/to/file`

Returns the raw file content.

### Get File Metadata
**GET** `/?file-path=/path/to/file&mode=metadata`

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

### Get Directory Listing
**GET** `/?dir-path=/path/to/dir`

Returns a JSON list of files and subdirectories.

**Optional Parameters:**
- `depth`: Integer (default `0`). If `> 0`, recursively lists contents up to the specified depth.

Example Response (`depth=0`):
```json
[
  {
    "name": "file.txt",
    "type": "file",
    "size": 1024,
    "owner": "user",
    "group": "staff",
    "permissions": "644"
  },
  {
    "name": "subdir",
    "type": "directory",
    "size": 0,
    "owner": "user",
    "group": "staff",
    "permissions": "755"
  }
]
```

### Get Directory Metadata
**GET** `/?dir-path=/path/to/dir&mode=metadata`

Returns JSON metadata for the directory itself.

### Error Responses
Errors are returned as JSON. If you use `file-path` for a directory or `dir-path` for a file, you will receive a **400 Bad Request**.

```json
{
  "error": true,
  "code": 400,
  "message": "Requested path is not a file (expected file-path)",
  "details": "Bad request syntax or unsupported method"
}
```

## API Stop Endpoint

You can stop the server remotely using an API call, but only if the server was started with the `--allow-api-stop` flag.

**Start with flag:**
```bash
python3 file_server.py --allow-api-stop ...
```

**Stop via API:**
```bash
curl "http://localhost:7200/?cmd=stop"
```

If the flag is not provided, this request will return `403 Forbidden`.

## Usage Examples

**Note:** Always quote the URL when using `curl` to prevent the shell from interpreting `&`.

> [!WARNING]
> **Self-Deletion Feature**: If you run the server with `--timeout` AND `--self-delete`, the server script (`file_server.py`) will **DELETE ITSELF** when the timeout expires.
> Example: `python3 file_server.py --timeout 300 --self-delete`

1.  **Get File Content**:
    ```bash
    curl "http://localhost:7200/?file-path=$(pwd)/file_server.py"
    ```

2.  **Get File Metadata**:
    ```bash
    curl "http://localhost:7200/?file-path=$(pwd)/file_server.py&mode=metadata"
    ```

3.  **List Directory (Immediate Children)**:
    ```bash
    curl "http://localhost:7200/?dir-path=$(pwd)"
    ```

4.  **Recursive Directory Listing (Depth 2)**:
    ```bash
    curl "http://localhost:7200/?dir-path=$(pwd)&depth=2"
    ```

5.  **Get Directory Metadata**:
    ```bash
    curl "http://localhost:7200/?dir-path=$(pwd)&mode=metadata"
    ```

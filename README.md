# Vanilla Python File API Server

A single-file, dependency-free Python HTTP server that exposes a REST-like API for file and directory operations. It uses only the Python Standard Library.

## Features

*   **File Serving**: Read file contents with correct MIME type detection.
*   **Directory Listing**: List directory contents (recursive support) as JSON.
*   **Metadata**: Retrieve detailed file/directory metadata (size, owner, permissions, timestamps).
*   **Scope Restriction**: Restrict access to specific directories for security.
*   **Daemon Mode**: Run as a background process (`--daemon`).
*   **Auto-Stop Timeout**: Automatically shut down after a specified duration (`--timeout`).
*   **Conditional Self-Deletion**: Option to delete the server script itself upon timeout (`--self-delete`).
*   **API Stop Endpoint**: Remotely stop the server via API call (`--allow-api-stop`).
*   **JSON Error Responses**: All errors are returned as structured JSON.

## Requirements

*   Python 3.6+
*   **Standard Library Only**: No `pip install` required.

## Installation

Simply download `file_server.py`.

```bash
# Verify all required libraries are available
python3 -c "import http.server, socketserver, os, json, urllib.parse, pwd, grp, argparse, sys, shutil, mimetypes, signal, atexit, time, threading; print('All libraries available')"
```

## Usage

### Basic Start
Start the server on default port 7200, serving files from the current directory (and subdirectories).

```bash
python3 file_server.py
```

### Command Line Arguments

| Argument | Description | Default |
| :--- | :--- | :--- |
| `--port PORT` | Port to run the server on. | `7200` |
| `--scope [DIR ...]` | Restrict access to these directories. If omitted, allows ALL. | `None` (All) |
| `--daemon` | Run as a background daemon process. | `False` |
| `--stop` | Stop a running daemon (uses PID file). | `False` |
| `--pid-file FILE` | Path to the PID file. | `file_server.pid` |
| `--timeout SECONDS` | Auto-stop the server after N seconds (Hard Limit). | `None` |
| `--idle-timeout SECONDS` | Auto-stop after N seconds of **inactivity**. | `None` |
| `--self-delete` | **Destructive**: Delete `file_server.py` when timeout expires. | `False` |
| `--allow-api-stop` | Allow stopping the server via `/?cmd=stop`. | `False` |

### Examples

**1. Serve specific directories on port 8080:**
```bash
python3 file_server.py --port 8080 --scope /var/www /tmp/public
```

**2. Run as a daemon:**
```bash
python3 file_server.py --daemon --pid-file /tmp/fs.pid
```

**3. Stop the daemon:**
```bash
python3 file_server.py --stop --pid-file /tmp/fs.pid
```

**4. Auto-stop after 5 minutes (Hard Limit):**
```bash
python3 file_server.py --timeout 300
```

**5. Auto-stop after 5 minutes of INACTIVITY:**
```bash
python3 file_server.py --idle-timeout 300
```

**6. Auto-stop AND Self-Delete (One-time use server):**
> [!WARNING]
> This will **DELETE** the `file_server.py` file when the timer expires.
```bash
python3 file_server.py --timeout 300 --self-delete
# OR
python3 file_server.py --idle-timeout 300 --self-delete
```

**7. Allow stopping via API:**
```bash
python3 file_server.py --allow-api-stop
# Then call: curl "http://localhost:7200/?cmd=stop"
```

---

## API Endpoints

All requests use the **GET** method.

### 1. Get File Content
**Parameter**: `file-path` (Absolute path)

```bash
curl "http://localhost:7200/?file-path=/path/to/file.txt"
```
*   **Success**: Returns file content (200 OK).
*   **Error**: 404 Not Found, 403 Forbidden (Scope), 400 Bad Request (if path is a directory).

### 2. List Directory
**Parameter**: `dir-path` (Absolute path)
**Optional**: `depth` (Recursion depth, default 0)

```bash
curl "http://localhost:7200/?dir-path=/path/to/dir"
# Recursive listing (depth 2)
curl "http://localhost:7200/?dir-path=/path/to/dir&depth=2"
```
*   **Success**: Returns JSON list of contents (200 OK).
*   **Response Format**:
    ```json
    [
      {
        "name": "file.txt",
        "type": "file",
        "size": 1234,
        "owner": "user",
        "group": "staff",
        "permissions": "644"
      },
      ...
    ]
    ```

### 3. Get Metadata
**Parameter**: `file-path` OR `dir-path`
**Parameter**: `mode=metadata`

```bash
curl "http://localhost:7200/?file-path=/path/to/file.txt&mode=metadata"
```
*   **Success**: Returns JSON metadata (200 OK).
*   **Response Format**:
    ```json
    {
      "path": "/path/to/file.txt",
      "type": "file",
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

### 4. Stop Server (API)
**Parameter**: `cmd=stop`
**Requirement**: Server must be started with `--allow-api-stop`.

```bash
curl "http://localhost:7200/?cmd=stop"
```
*   **Success**: Returns `{"message": "Server stopping..."}` (200 OK) and shuts down.
*   **Error**: 403 Forbidden (if flag not enabled).

## Error Handling

Errors are returned as JSON:
```json
{
  "error": true,
  "code": 404,
  "message": "File/Directory not found",
  "details": "..."
}
```

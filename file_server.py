import http.server  # Provides the basic HTTP server classes (HTTPServer, BaseHTTPRequestHandler)
import socketserver # Mixin class used by HTTPServer for TCP socket handling
import os           # Operating system interfaces (file system, process management, etc.)
import json         # JSON encoder/decoder for API responses
import urllib.parse # Parsing URLs and query parameters
import pwd          # Password database access (to get file owner name)
import grp          # Group database access (to get file group name)
import argparse     # Command-line argument parsing
import sys          # System-specific parameters and functions (stdin/stdout, exit)

import shutil       # High-level file operations (used for efficient file copying/streaming)
import mimetypes    # Map filenames to MIME types (e.g., .html -> text/html)
import signal       # Signal handling (SIGTERM) for graceful shutdown
import atexit       # Register functions to be called when the program exits (cleanup)
import time         # Time access and conversions (sleep)
import threading    # Thread-based parallelism (used for auto-stop timer)

# Default configuration
DEFAULT_PORT = 7200
# Default scope is empty (implies no restriction if not provided, or we can default to CWD if we want safe default? 
# User said: "if now paths provided, it should allow reading any file."
# So default should be empty list.
DEFAULT_SCOPES = []
DEFAULT_PID_FILE = "file_server.pid"

class FileRequestHandler(http.server.BaseHTTPRequestHandler):
    """
    Custom HTTP request handler to serve files and directories.
    Handles GET requests with support for:
    - File content serving
    - Directory listing (recursive)
    - Metadata retrieval
    - Scope restriction
    """
    def do_GET(self):
        """
        Handle GET requests.
        Parses query parameters, performs security checks (scope, path traversal),
        and dispatches to the appropriate handler (content or metadata).
        """
        # Update last activity time for idle timeout
        if hasattr(self.server, 'last_activity'):
            self.server.last_activity = time.time()

        parsed_url = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Check for command
        cmd = query_params.get('cmd', [None])[0]
        if cmd == 'stop':
            if getattr(self.server, 'allow_api_stop', False):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"message": "Server stopping..."}).encode('utf-8'))
                
                def kill_me():
                    self.server.shutdown()
                threading.Thread(target=kill_me).start()
                return
            else:
                self.send_error(403, "API stop not allowed (start with --allow-api-stop)")
                return

        # Extract parameters
        # file-path: Path to a file to read
        # dir-path: Path to a directory to list
        # mode: 'content' (default) or 'metadata'
        # depth: Recursion depth for directory listing
        file_path_param = query_params.get('file-path', [None])[0]
        dir_path_param = query_params.get('dir-path', [None])[0]
        mode = query_params.get('mode', ['content'])[0]
        try:
            depth = int(query_params.get('depth', [0])[0])
        except ValueError:
            depth = 0
        
        # Validate that exactly one path parameter is provided
        if file_path_param and dir_path_param:
            self.send_error(400, "Ambiguous request: Cannot provide both 'file-path' and 'dir-path'")
            return
            
        if not file_path_param and not dir_path_param:
            self.send_error(400, "Missing 'file-path' or 'dir-path' query parameter")
            return

        target_param = file_path_param if file_path_param else dir_path_param
        is_file_request = bool(file_path_param)

        # Security: Resolve absolute path and check against scope
        try:
            # Resolve target path to an absolute path, normalizing '..' components
            if os.path.isabs(target_param):
                target_path = os.path.normpath(target_param)
            else:
                target_path = os.path.normpath(os.path.abspath(target_param))
            
            # Scope Check: Ensure the path is within one of the allowed scopes
            allowed = False
            if not self.server.scopes:
                # No scopes provided -> Allow all
                allowed = True
            else:
                for scope in self.server.scopes:
                    # Check if the scope is a parent of the target path
                    if os.path.commonpath([scope, target_path]) == scope:
                        allowed = True
                        break
            
            if not allowed:
                 self.send_error(403, "Access denied: Path outside of allowed scopes")
                 return
                 
            if not os.path.exists(target_path):
                self.send_error(404, "File/Directory not found")
                return
                
            # Type Enforcement: Ensure the path matches the requested type (file vs dir)
            if is_file_request:
                if not os.path.isfile(target_path):
                    self.send_error(400, "Requested path is not a file (expected file-path)")
                    return
            else:
                if not os.path.isdir(target_path):
                    self.send_error(400, "Requested path is not a directory (expected dir-path)")
                    return

        except Exception as e:
            self.send_error(500, f"Internal server error resolving path: {str(e)}")
            return

        # Dispatch based on mode and type
        if mode == 'metadata':
            self.handle_metadata(target_path)
        else:
            if is_file_request:
                self.handle_content(target_path)
            else:
                self.handle_directory_listing(target_path, depth)

    def handle_metadata(self, file_path):
        """
        Retrieves and returns metadata for a file or directory.
        Returns JSON containing size, owner, group, permissions, and timestamps.
        """
        try:
            stat_info = os.stat(file_path)
            
            # Get owner and group names
            try:
                owner_name = pwd.getpwuid(stat_info.st_uid).pw_name
            except KeyError:
                owner_name = str(stat_info.st_uid)
                
            try:
                group_name = grp.getgrgid(stat_info.st_gid).gr_name
            except KeyError:
                group_name = str(stat_info.st_gid)

            metadata = {
                "path": file_path,
                "type": "directory" if os.path.isdir(file_path) else "file",
                "size": stat_info.st_size,
                "owner": owner_name,
                "group": group_name,
                "permissions": oct(stat_info.st_mode)[-3:],
                "uid": stat_info.st_uid,
                "gid": stat_info.st_gid,
                "atime": stat_info.st_atime,
                "mtime": stat_info.st_mtime,
                "ctime": stat_info.st_ctime,
            }
            
            response_content = json.dumps(metadata, indent=2).encode('utf-8')
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(response_content))
            self.end_headers()
            self.wfile.write(response_content)
            
        except Exception as e:
            self.send_error(500, f"Error retrieving metadata: {str(e)}")

    def handle_content(self, file_path, depth=0):
        """
        Serves the content of a file.
        Detects MIME type and streams content using shutil.copyfileobj for efficiency.
        """
        try:
            # Detect MIME type
            mime_type, _ = mimetypes.guess_type(file_path)
            if mime_type is None:
                mime_type = 'application/octet-stream'

            # Get file size for Content-Length
            file_size = os.path.getsize(file_path)

            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.send_header('Content-Length', file_size)
            self.end_headers()
            
            # Stream file content
            with open(file_path, 'rb') as f:
                shutil.copyfileobj(f, self.wfile)
            
        except PermissionError:
            self.send_error(403, "Permission denied reading file")
        except Exception as e:
            self.send_error(500, f"Error reading file: {str(e)}")

    def handle_directory_listing(self, dir_path, depth=0):
        """
        Serves a JSON listing of a directory's contents.
        Supports recursive listing via the 'depth' parameter.
        """
        try:
            contents = self._get_directory_contents(dir_path, depth)
            
            response_content = json.dumps(contents, indent=2).encode('utf-8')
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', len(response_content))
            self.end_headers()
            self.wfile.write(response_content)
            
        except PermissionError:
            self.send_error(403, "Permission denied listing directory")
        except Exception as e:
            self.send_error(500, f"Error listing directory: {str(e)}")

    def _get_directory_contents(self, dir_path, depth):
        """
        Helper to recursively fetch directory contents.
        Returns a list of dictionaries with file/dir details.
        """
        contents = []
        with os.scandir(dir_path) as it:
            for entry in it:
                entry_type = "directory" if entry.is_dir() else "file"
                
                # Get metadata
                try:
                    stat_info = entry.stat()
                    size = stat_info.st_size if entry.is_file() else 0
                    permissions = oct(stat_info.st_mode)[-3:]
                    
                    try:
                        owner = pwd.getpwuid(stat_info.st_uid).pw_name
                    except KeyError:
                        owner = str(stat_info.st_uid)
                        
                    try:
                        group = grp.getgrgid(stat_info.st_gid).gr_name
                    except KeyError:
                        group = str(stat_info.st_gid)
                except OSError:
                    # Fallback if stat fails
                    size = 0
                    permissions = ""
                    owner = ""
                    group = ""
                
                item = {
                    "name": entry.name,
                    "type": entry_type,
                    "size": size,
                    "owner": owner,
                    "group": group,
                    "permissions": permissions
                }
                
                if entry.is_dir() and depth > 0:
                    try:
                        item["contents"] = self._get_directory_contents(entry.path, depth - 1)
                    except PermissionError:
                         item["contents"] = None
                         item["error"] = "Permission denied"
                
                contents.append(item)
        
        # Sort by type (dirs first) then name
        contents.sort(key=lambda x: (0 if x['type'] == 'directory' else 1, x['name']))
        return contents

    def send_error(self, code, message=None, explain=None):
        """
        Override send_error to return JSON instead of HTML.
        """
        if message is None:
            message = self.responses.get(code, ('', ''))[0]
        if explain is None:
            explain = self.responses.get(code, ('', ''))[1]
            
        error_response = {
            "error": True,
            "code": code,
            "message": message,
            "details": explain
        }
        
        try:
            content = json.dumps(error_response, indent=2).encode('utf-8')
            
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(content))
            self.end_headers()
            
            if self.command != 'HEAD' and code >= 200 and code not in (204, 304):
                self.wfile.write(content)
        except Exception:
            # If sending error fails, we can't do much more
            pass

def daemonize(pid_file):
    """
    Detach a process from the controlling terminal and run it in the
    background as a daemon.
    Uses the double-fork magic to ensure the process is fully detached.
    """
    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"fork #1 failed: {e.errno} ({e.strerror})\n")
        sys.exit(1)

    # decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)

    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # exit from second parent
            sys.exit(0)
    except OSError as e:
        sys.stderr.write(f"fork #2 failed: {e.errno} ({e.strerror})\n")
        sys.exit(1)

    # redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = open(os.devnull, 'r')
    so = open(os.devnull, 'a+')
    se = open(os.devnull, 'a+')
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

    # write pidfile
    pid = str(os.getpid())
    with open(pid_file, 'w+') as f:
        f.write(f"{pid}\n")
    
    # register atexit to remove pidfile
    atexit.register(lambda: os.remove(pid_file))

def stop_server(pid_file):
    """
    Stop the daemon process specified in the pid_file.
    Sends SIGTERM to the process ID found in the file.
    """
    if not os.path.exists(pid_file):
        print(f"PID file '{pid_file}' not found. Is the server running?")
        return

    try:
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())
    except ValueError:
        print(f"Invalid PID in file '{pid_file}'.")
        return

    try:
        while True:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.1)
    except OSError as err:
        err = str(err)
        if "No such process" in err:
            if os.path.exists(pid_file):
                os.remove(pid_file)
            print("Server stopped.")
        else:
            print(str(err))
            sys.exit(1)

def self_delete_script(script_path):
    """
    Deletes the script file at the given path.
    This function is kept separate to allow easy removal of the self-deletion feature.
    """
    try:
        if os.path.exists(script_path):
            os.remove(script_path)
    except Exception:
        pass

def run(scopes, port, daemon=False, stop=False, pid_file=None, timeout=None, self_delete=False, allow_api_stop=False, idle_timeout=None):
    """
    Main entry point to run the server.
    Handles configuration, daemonization, and starting the HTTPServer.
    """
    # Mutual exclusion check for timeout and idle_timeout
    if timeout and idle_timeout:
        print("Error: Cannot use both --timeout and --idle-timeout. Please choose one.")
        sys.exit(1)

    # Resolve PID file path
    if pid_file:
        pid_file = os.path.abspath(pid_file)
    else:
        pid_file = os.path.abspath(DEFAULT_PID_FILE)

    if stop:
        stop_server(pid_file)
        return

    # Normalize scopes
    normalized_scopes = []
    if scopes:
        for scope in scopes:
            abs_scope = os.path.abspath(scope)
            if not os.path.isdir(abs_scope):
                print(f"Warning: Scope directory '{scope}' does not exist or is not a directory. Skipping.")
            else:
                normalized_scopes.append(abs_scope)
        
        if not normalized_scopes and scopes:
             print("Error: No valid scopes found from provided list.")
             sys.exit(1)

    if daemon:
        print(f"Starting server in daemon mode on port {port}...")
        daemonize(pid_file)
    else:
        print(f"Starting server on port {port}...")
        # Write PID file for non-daemon mode too
        pid = str(os.getpid())
        with open(pid_file, 'w+') as f:
            f.write(f"{pid}\n")
        atexit.register(lambda: os.remove(pid_file) if os.path.exists(pid_file) else None)

    # In daemon mode, these prints go to /dev/null
    if normalized_scopes:
        print(f"Serving files from scopes: {normalized_scopes}")
    else:
        print("Serving files from ALL locations (No scope restriction)")
    
    server_address = ('', port)
    httpd = http.server.HTTPServer(server_address, FileRequestHandler)
    httpd.scopes = normalized_scopes
    httpd.allow_api_stop = allow_api_stop
    
    # Capture script path here to ensure it's available in the thread
    script_path = os.path.abspath(__file__)
    
    def shutdown_server():
        httpd.shutdown()
        # Self-deletion logic
        if self_delete:
            self_delete_script(script_path)

    # Auto-stop timeout (Hard limit)
    if timeout:
        print(f"Server will auto-stop in {timeout} seconds.")
        t = threading.Timer(timeout, shutdown_server)
        t.start()
        
    # Idle timeout (Inactivity limit)
    if idle_timeout:
        print(f"Server will auto-stop after {idle_timeout} seconds of inactivity.")
        httpd.last_activity = time.time()
        
        def monitor_idle():
            while True:
                time.sleep(1)
                if time.time() - httpd.last_activity > idle_timeout:
                    shutdown_server()
                    break
        
        t = threading.Thread(target=monitor_idle, daemon=True)
        t.start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        if not daemon:
            print("\nServer stopped.")
        httpd.server_close()
    finally:
        # Ensure timer is cancelled if manual stop happens first
        if timeout and 't' in locals() and isinstance(t, threading.Timer):
            t.cancel()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Vanilla Python File API Server")
    parser.add_argument('--scope', nargs='*', default=DEFAULT_SCOPES, help=f"Directory scopes to serve files from. If not provided, allows all. (default: None)")
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help=f"Port to run the server on (default: {DEFAULT_PORT})")
    parser.add_argument('--daemon', action='store_true', help="Run as a daemon process")
    parser.add_argument('--stop', action='store_true', help="Stop the running daemon")
    parser.add_argument('--pid-file', default=DEFAULT_PID_FILE, help=f"Path to PID file (default: {DEFAULT_PID_FILE})")
    parser.add_argument('--timeout', type=int, help="Auto-stop the server after N seconds (hard limit)")
    parser.add_argument('--idle-timeout', type=int, help="Auto-stop the server after N seconds of inactivity")
    parser.add_argument('--self-delete', action='store_true', help="Delete the server script file when timeout expires")
    parser.add_argument('--allow-api-stop', action='store_true', help="Allow stopping the server via API call (/?cmd=stop)")
    
    args = parser.parse_args()
    
    run(args.scope, args.port, args.daemon, args.stop, args.pid_file, args.timeout, args.self_delete, args.allow_api_stop, args.idle_timeout)

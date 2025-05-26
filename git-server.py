import os
import sys
import http.server
import socketserver
import subprocess
from urllib.parse import urlparse
import base64
import json
import logging
from logging.handlers import RotatingFileHandler
from permission_control import PermissionControl
import argparse

# 全局配置对象
SERVER_CONFIG = {}

# 配置日志
def setup_logger(logger):
    """Setup logging system with daily rotating files"""
    # Get log directory from config, fallback to default using current working directory
    log_dir = SERVER_CONFIG['log_dir']
    os.makedirs(log_dir, exist_ok=True)
    
    # Set log file path
    log_file = os.path.join(log_dir, 'git_server.log')
    
    logger.setLevel(logging.INFO)
    
    # Create TimedRotatingFileHandler with the properly formatted filename
    file_handler = logging.handlers.TimedRotatingFileHandler(
        log_file,
        when='midnight',     # Rotate at midnight
        interval=1,          # One day per file
        backupCount=2,       # Keep 2 backup files (3 files total)
        encoding='utf-8'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler()
    
    # Set log format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

# 初始化日志系统
logger = logging.getLogger('GitServer')

def load_server_config(config_path=None):
    """加载服务器配置"""
    if config_path is None:
        config_path = os.path.join(os.getcwd(), 'config.json')
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            
        # 验证必需的配置项
        required_keys = ['git_repo_path', 'git_http_backend', 'log_dir']
        for key in required_keys:
            if key not in config:
                raise KeyError(key)
        
        return config
    except FileNotFoundError:
        logger.error(f"Configuration file not found at {config_path}")
        sys.exit(1)
    except KeyError as e:
        logger.error(f"Missing required configuration key: {e}")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error(f"Invalid JSON format in configuration file")
        sys.exit(1)

COMMANDS_READONLY = [
    'git-upload-pack',
    'git upload-pack',
    'git-upload-archive',
    'git upload-archive',
    ]

COMMANDS_WRITE = [
    'git-receive-pack',
    'git receive-pack',
    ]

COMMANDS_ALL = COMMANDS_READONLY + COMMANDS_WRITE

class GitHttpServer(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.git_repo_path = SERVER_CONFIG['git_repo_path']
        self.git_http_backend = SERVER_CONFIG['git_http_backend']
        self.server_port = SERVER_CONFIG['server_port']
        
        # Create .conf directory if it doesn't exist
        conf_dir = os.path.join(self.git_repo_path, 'conf')
        if not os.path.exists(conf_dir):
            os.makedirs(conf_dir)
        
        # Store config files in .conf directory
        self.htpasswd_file = os.path.join(conf_dir, '.htpasswd')
        self.permission_file = os.path.join(conf_dir, '.permissions')
        
        # Call parent class initialization
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """处理HTTP GET请求
        验证用户身份并处理Git相关请求"""
        success, username = self.authenticate()  # 获取认证结果和用户名
        if success:
            self.handle_git_request(username)

    def do_POST(self):
        """处理HTTP POST请求
        验证用户身份并处理Git相关请求"""
        success, username = self.authenticate()  # 获取认证结果和用户名
        if success:
            self.handle_git_request(username)

    def authenticate(self):
        """验证用户身份
        解析HTTP基本认证头，验证用户名和密码
        返回值:
            tuple: (认证是否成功(bool), 用户名(str))"""
        auth_header = self.headers.get('Authorization')
        if auth_header is None:
            self.send_authenticate()
            return False, None
        
        try:
            auth_type, auth_string = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                self.send_authenticate()
                return False, None
            
            username, password = base64.b64decode(auth_string).decode().split(':', 1)
            if self.verify_password(username, password):
                return True, username  # 返回验证成功的用户名
        except Exception as e:
            logger.warning(f"Authentication error: {str(e)}")
        
        self.send_authenticate()
        return False, None

    def send_authenticate(self):
        """发送HTTP基本认证请求
        向客户端发送401状态码要求进行身份认证"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Git Repository"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Authentication required")

    def setup(self):
        """服务器初始化设置
        初始化权限控制系统并调用父类初始化方法"""
        # 初始化权限控制
        logger.info("Initializing permission control")  # Debug log
        self.permission_control = PermissionControl(self.permission_file)
        super().setup()
    
    def verify_password(self, username, password):
        """验证用户密码"""
        try:
            with open(self.htpasswd_file, 'r') as f:
                for line in f:
                    stored_user, stored_pass = line.strip().split(':')
                    if username == stored_user:
                        return password == stored_pass
        except FileNotFoundError:
            return False
        return False

    def handle_git_request(self, username):
        """处理Git HTTP请求"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path.lstrip('/')
        logger.info(f"Processing {self.command} request for: {path}")

        # 检查仓库是否存在
        if not self._check_repository(path):
            return

        # 检查权限
        if not self._check_access_permission(path, username):
            return

        # 设置环境变量
        env = self._setup_git_environment(path, username, parsed_path)

        # 执行git-http-backend
        self._execute_git_backend(env)

    def _get_repo_name(self, path):
        """
        从请求路径中解析出仓库名称
        :param path: 请求路径 (例如: 'test.git/info/refs' 或 'test.git/git-receive-pack')
        :return: 仓库名称 (例如: 'test.git')
        """
        repo_parts = path.split('/')
        if not repo_parts:
            return None
            
        # 获取仓库名称
        repo_name = repo_parts[0]
        if not repo_name.endswith('.git'):
            repo_name = f"{repo_name}.git"
        
        return repo_name

    def _check_repository(self, path):
        """检查仓库是否存在"""
        logger.info(f"Checking repository path: {path}")
      
        # 从路径中获取仓库名称
        repo_name = self._get_repo_name(path)
        if not repo_name:
            self.send_error(404, "Invalid repository path")
            return False
        
        # 检查仓库是否存在
        repo_path = os.path.join(self.git_repo_path, repo_name)
        if not os.path.exists(repo_path):
            self.send_error(404, f"Repository {repo_name} not found")
            return False
        
        return True

    def _get_access_type(self, path):
        """
        根据请求路径判断访问类型
        :param path: 请求路径
        :return: 'read' 或 'write'
        """
        # 默认为读操作
        access_type = 'read'
        
        # 检查是否为写操作命令
        for cmd in COMMANDS_WRITE:
            if cmd in path:
                access_type = 'write'
                break
                
        return access_type

    def _check_access_permission(self, path, username):
        """检查访问权限"""
        access_type = self._get_access_type(path)
        
        # 检查权限
        if not self.check_permission(path, username, access_type):
            self.send_error(403, f"Permission denied: {username} does not have {access_type} access")
            return False
            
        return True

    def _setup_git_environment(self, path, username, parsed_path):
        """设置Git环境变量"""
        env = os.environ.copy()
        # 基础环境变量
        env.update({
            'REQUEST_METHOD': self.command,
            'GIT_PROJECT_ROOT': self.git_repo_path,
            'PATH_INFO': '/' + path,
            'QUERY_STRING': parsed_path.query,
            'REMOTE_USER': username,
            'REMOTE_ADDR': self.client_address[0],
            'CONTENT_TYPE': self.headers.get('content-type', ''),
            'CONTENT_LENGTH': self.headers.get('content-length', ''),
            'GIT_HTTP_EXPORT_ALL': '1',
            'GATEWAY_INTERFACE': 'CGI/1.1',
            'SERVER_PROTOCOL': self.protocol_version,
            'HTTP_HOST': self.headers.get('host', ''),
            'SERVER_NAME': 'localhost',
            'SERVER_PORT': str(self.server_port)  # Use actual server port
        })

        logger.debug(f"Git environment for {username}: {env}")

        # Git提交相关环境变量
        if self._get_access_type(path) == "write":
            env['GIT_HTTP_BACKEND_ENABLE_RECEIVE_PACK'] = '1'
            env['GIT_COMMITTER_NAME'] = username
            env['REMOTE_USER_EMAIL'] = f"{username}@git.com"

        return env

    def _execute_git_backend(self, env):
        """执行git-http-backend并处理响应"""
        try:
            process = subprocess.Popen(
                self.git_http_backend,
                env=env,
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )

            # 处理请求数据
            if self.command == 'POST':
                content_length = int(self.headers.get('content-length', 0))
                post_data = self.rfile.read(content_length)
                stdout, stderr = process.communicate(input=post_data)
            else:
                stdout, stderr = process.communicate()

            # 处理错误输出
            if stderr:
                logger.error(f"Git backend error: {stderr.decode('utf-8')}")

            # 处理响应
            self._handle_git_response(stdout)

        except Exception as e:
            logger.error(f"Error executing git backend: {str(e)}")
            self.send_error(500, str(e))

    def _handle_git_response(self, stdout):
        """处理git-http-backend的响应"""
        if not stdout:
            self.send_error(500, "No response from git-http-backend")
            return

        # 分离响应头和响应体
        response = stdout.split(b'\r\n\r\n', 1)
        if not response:
            return

        headers = response[0].split(b'\r\n')
        status_line = headers[0].decode('utf-8')

        # 设置响应状态码
        if status_line.startswith('Status:'):
            status_code = int(status_line.split(' ')[1])
            self.send_response(status_code)
        else:
            self.send_response(200)

        # 发送响应头
        for header in headers[1:]:
            if b':' in header:
                key, value = header.split(b':', 1)
                self.send_header(key.decode('utf-8').strip(), 
                               value.decode('utf-8').strip())

        self.end_headers()

        # 发送响应体
        if len(response) > 1:
            self.wfile.write(response[1])
            
    def check_permission(self, repo_path, username, access_type):
        """
        检查用户是否有仓库的指定权限
        :param repo_path: 仓库路径 (例如: 'test.git/info/refs' 或 'test.git/git-receive-pack')
        :param username: 用户名
        :param access_type: 权限类型 ('read' or 'write')
        :return: bool
        """

        # 获取仓库名称 (例如: 'test.git')
        repo_name = self._get_repo_name(repo_path)
        if not repo_name:  # 如果路径中没有仓库名称，则返回False
            return False
        if not repo_name.endswith('.git'):
            repo_name = f"{repo_name}.git"
        
        logger.info(f"Checking permissions: user={username}, repo={repo_name}, access={access_type}")
        return self.permission_control.check_permission(repo_name, username, access_type)

    def log_message(self, format, *args):
        """Override to log HTTP requests to our logger"""
        message = f"{self.client_address[0]} - - [{self.log_date_time_string()}] {format%args}"
        logger.info(message)

def set_default_config():
    global SERVER_CONFIG
    """Set default values for optional configuration items"""
    defaults = {
        'server_port': 8000,
        'log_dir': os.path.join(os.getcwd(), 'logs'),
    }
    
    for key, default_value in defaults.items():
        if key not in SERVER_CONFIG:
            SERVER_CONFIG[key] = default_value

def verify_git_backend():
    """Verify that git-http-backend exists and is executable"""
    backend_path = SERVER_CONFIG.get('git_http_backend')
    if not backend_path:
        logger.error("git_http_backend path not configured")
        sys.exit(1)
        
    if not os.path.exists(backend_path):
        logger.error(f"git-http-backend not found at: {backend_path}")
        sys.exit(1)
        
    if not os.path.isfile(backend_path):
        logger.error(f"git-http-backend path is not a file: {backend_path}")
        sys.exit(1)
        
    if not os.access(backend_path, os.X_OK):
        logger.error(f"git-http-backend is not executable: {backend_path}")
        sys.exit(1)
        
    logger.info(f"git-http-backend verified at: {backend_path}")

if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Git HTTP Server')
    parser.add_argument('--config', '-c', 
                       help='Path to config.json file',
                       required=True)
    args = parser.parse_args()
    
    # Load configuration and set defaults
    SERVER_CONFIG.update(load_server_config(args.config))
    set_default_config()
       
    setup_logger(logger)
    
    # Verify git-http-backend before starting
    verify_git_backend()
 
    port = SERVER_CONFIG['server_port']
    
    # Log configuration info
    logger.info("Server Configuration:")
    logger.info("-" * 20)
    logger.info(f"Config File: {args.config}")
    logger.info(f"Repository Path: {SERVER_CONFIG['git_repo_path']}")
    logger.info(f"HTTP Backend: {SERVER_CONFIG['git_http_backend']}")
    logger.info(f"Log Directory: {SERVER_CONFIG['log_dir']}")  # 添加日志目录信息
    logger.info(f"Server Port: {port}")
    logger.info("-" * 20)
    
    # Start server
    with socketserver.TCPServer(("", port), GitHttpServer) as httpd:
        logger.info(f"Git HTTP Server started on port {port}")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down server...")
            httpd.server_close()
        finally:
            logger.info("Server stopped")
            logger.info("-" * 20)
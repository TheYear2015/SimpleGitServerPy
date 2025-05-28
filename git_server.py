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
import argparse
from typing import Dict, Tuple, Optional

from permission_control import PermissionControl
from config_validator import ConfigValidator

# 全局配置
SERVER_CONFIG: Dict[str, any] = {}

# Git 命令常量
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

# 全局配置对象
SERVER_CONFIG = {}

# 配置日志
def setup_logger(logger):
    """设置每日轮转的日志系统"""
    log_dir = SERVER_CONFIG['log_dir']
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, 'git_server.log')
    logger.setLevel(logging.INFO)
    
    file_handler = logging.handlers.TimedRotatingFileHandler(
        log_file,
        when='midnight',
        interval=1,
        backupCount=2,
        encoding='utf-8'
    )
    
    console_handler = logging.StreamHandler()
    
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
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
            
        # 验证必需的配置项（git_repo_path、git_http_backend、log_dir）
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

class GitHttpServer(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.git_repo_path = SERVER_CONFIG['git_repo_path']
        self.git_http_backend = SERVER_CONFIG['git_http_backend']
        self.server_port = SERVER_CONFIG['server_port']
        
        # 如果不存在则创建 .conf 目录
        conf_dir = os.path.join(self.git_repo_path, 'conf')
        os.makedirs(conf_dir, exist_ok=True)
        
        # 在 .conf 目录中存储配置文件
        self.htpasswd_file = os.path.join(conf_dir, '.htpasswd')
        self.permission_file = os.path.join(conf_dir, '.permissions')
        
        # 调用父类初始化
        super().__init__(*args, **kwargs)
    
    def do_GET(self):
        """处理 HTTP GET 请求"""
        success, username = self.authenticate()
        if success:
            self.handle_git_request(username)

    def do_POST(self):
        """处理 HTTP POST 请求"""
        success, username = self.authenticate()
        if success:
            self.handle_git_request(username)

    def authenticate(self) -> Tuple[bool, Optional[str]]:
        """基本用户认证"""
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            self.send_authenticate()
            return False, None
            
        try:
            auth_type, auth_string = auth_header.split(' ', 1)
            if auth_type.lower() != 'basic':
                self.send_authenticate()
                return False, None
                
            username, password = base64.b64decode(auth_string).decode().split(':', 1)
            if self.verify_password(username, password):
                return True, username
                
        except Exception as e:
            logger.warning(f"Authentication error: {str(e)}")
            
        self.send_authenticate()
        return False, None

    def send_authenticate(self):
        """发送认证请求"""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Git Repository"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"Authentication required")

    def verify_password(self, username: str, password: str) -> bool:
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
    
    def setup(self):
        """服务器初始化"""
        logger.info("Initializing permission control")
        self.permission_control = PermissionControl(self.permission_file)
        super().setup()

    def handle_git_request(self, username: str):
        """处理 Git 请求"""
        parsed_path = urlparse(self.path)
        path = parsed_path.path.lstrip('/')
        logger.info(f"Processing {self.command} request for: {path}")

        if not self._check_repository(path):
            return

        if not self._check_access_permission(path, username):
            return

        env = self._setup_git_environment(path, username, parsed_path)
        self._execute_git_backend(env)
        
    def _get_repo_name(self, path: str) -> Optional[str]:
        """从路径中获取仓库名称"""
        if not path:
            return None
            
        repo_parts = path.split('/')
        if not repo_parts:
            return None
            
        repo_name = repo_parts[0]
        if not repo_name:
            return None
            
        if not repo_name.endswith('.git'):
            repo_name = f"{repo_name}.git"
        
        return repo_name

    def _check_repository(self, path: str) -> bool:
        """检查仓库是否存在"""
        logger.info(f"Checking repository path: {path}")
        
        repo_name = self._get_repo_name(path)
        if not repo_name:
            self.send_error(404, "Invalid repository path")
            return False
        
        repo_path = os.path.join(self.git_repo_path, repo_name)
        if not os.path.exists(repo_path):
            self.send_error(404, f"Repository {repo_name} not found")
            return False
        
        return True

    def _get_access_type(self, path: str) -> str:
        """获取访问类型"""
        access_type = 'read'
        for cmd in COMMANDS_WRITE:
            if cmd in path:
                access_type = 'write'
                break
        return access_type

    def _check_access_permission(self, path: str, username: str) -> bool:
        """检查访问权限"""
        access_type = self._get_access_type(path)
        if not self.check_permission(path, username, access_type):
            self.send_error(403, f"Permission denied: {username} does not have {access_type} access")
            return False
        return True

    def _setup_git_environment(self, path: str, username: str, parsed_path) -> Dict[str, str]:
        """设置 Git 环境"""
        env = os.environ.copy()
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
            'SERVER_PORT': str(self.server_port)
        })

        if self._get_access_type(path) == "write":
            env['GIT_HTTP_BACKEND_ENABLE_RECEIVE_PACK'] = '1'
            env['GIT_COMMITTER_NAME'] = username
            env['REMOTE_USER_EMAIL'] = f"{username}@git.com"

        return env

    def _execute_git_backend(self, env: Dict[str, str]):
        """执行 git-http-backend"""
        try:
            process = subprocess.Popen(
                self.git_http_backend,
                env=env,
                stdout=subprocess.PIPE,
                stdin=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )

            if self.command == 'POST':
                content_length = int(self.headers.get('content-length', 0))
                post_data = self.rfile.read(content_length)
                stdout, stderr = process.communicate(input=post_data)
            else:
                stdout, stderr = process.communicate()

            if stderr:
                logger.error(f"Git backend error: {stderr.decode('utf-8')}")

            self._handle_git_response(stdout)

        except Exception as e:
            logger.error(f"Error executing git backend: {str(e)}")
            self.send_error(500, str(e))

    def _handle_git_response(self, stdout: bytes):
        """处理 git 响应"""
        if not stdout:
            self.send_error(500, "No response from git-http-backend")
            return

        response = stdout.split(b'\r\n\r\n', 1)
        if not response:
            return

        headers = response[0].split(b'\r\n')
        status_line = headers[0].decode('utf-8')

        if status_line.startswith('Status:'):
            status_code = int(status_line.split(' ')[1])
            self.send_response(status_code)
        else:
            self.send_response(200)

        for header in headers[1:]:
            if b':' in header:
                key, value = header.split(b':', 1)
                self.send_header(key.decode('utf-8').strip(), 
                               value.decode('utf-8').strip())

        self.end_headers()

        if len(response) > 1:
            self.wfile.write(response[1])
            
    def check_permission(self, repo_path: str, username: str, access_type: str) -> bool:
        """检查用户权限"""
        repo_name = self._get_repo_name(repo_path)
        if not repo_name:
            return False
            
        if not repo_name.endswith('.git'):
            repo_name = f"{repo_name}.git"
        
        logger.info(f"Checking permissions: user={username}, repo={repo_name}, access={access_type}")
        return self.permission_control.check_permission(repo_name, username, access_type)

    def log_message(self, format: str, *args):
        """记录日志消息"""
        message = f"{self.client_address[0]} - - [{self.log_date_time_string()}] {format%args}"
        logger.info(message)

def set_default_config():
    """设置可选配置项的默认值"""
    global SERVER_CONFIG
    defaults = {
        'server_port': 8000,
        'log_dir': os.path.join(os.getcwd(), 'logs'),
    }
    
    for key, default_value in defaults.items():
        if key not in SERVER_CONFIG:
            SERVER_CONFIG[key] = default_value

def verify_git_backend():
    """验证 git-http-backend 是否存在且可执行"""
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
    parser = argparse.ArgumentParser(description='Git HTTP Server')
    parser.add_argument('--config', '-c', 
                       help='Path to config.json file',
                       required=True)
    args = parser.parse_args()
    
    try:
        # 加载配置
        with open(args.config, 'r') as f:
            config = json.load(f)
        SERVER_CONFIG.update(ConfigValidator.validate_config(config, logger))
        set_default_config()
        
        setup_logger(logger)
        verify_git_backend()
        
        port = SERVER_CONFIG['server_port']
        
        # 记录配置信息
        logger.info("Server Configuration:")
        logger.info("-" * 20)
        for key, value in SERVER_CONFIG.items():
            logger.info(f"{key}: {value}")
        logger.info("-" * 20)
        
        # 启动服务器
        server = socketserver.TCPServer(("", port), GitHttpServer)
        server.allow_reuse_address = True
        
        logger.info(f"Git HTTP Server started on port {port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down server...")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            server.server_close()
            logger.info("Server stopped")
            logger.info("-" * 20)
            
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
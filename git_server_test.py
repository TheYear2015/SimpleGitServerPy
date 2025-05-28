import unittest
import os
import json
import logging
import shutil
import tempfile
import base64
from unittest.mock import MagicMock, patch
import git_server
from git_server import (
    GitHttpServer, setup_logger, load_server_config,
    SERVER_CONFIG
)
from io import BytesIO


class TestGitHttpServer(unittest.TestCase):
    def setUp(self):
        """每个测试用例执行前的设置"""
        # 创建临时测试目录
        self.test_dir = tempfile.mkdtemp()
        self.git_repo_path = os.path.join(self.test_dir, 'repos')
        self.log_dir = os.path.join(self.test_dir, 'logs')
        os.makedirs(self.git_repo_path)
        
        # 创建测试用的 git-http-backend 文件
        self.backend_path = os.path.join(self.test_dir, 'git-http-backend')
        with open(self.backend_path, 'w') as f:
            f.write('#!/bin/sh\necho "Mock git-http-backend"')
        os.chmod(self.backend_path, 0o755)  # 设置可执行权限
        
        # 创建测试用的权限文件
        self.conf_dir = os.path.join(self.git_repo_path, 'conf')
        os.makedirs(self.conf_dir, exist_ok=True)
        self.htpasswd_file = os.path.join(self.conf_dir, '.htpasswd')
        self.permission_file = os.path.join(self.conf_dir, '.permissions')
        
        # 设置测试用户和密码
        with open(self.htpasswd_file, 'w') as f:
            f.write('alice:password123\n')
            f.write('bob:password456\n')
        
        # 设置测试权限
        permissions = {
            'test-repo.git': {
                'alice': 'rw',
                'bob': 'r'
            }
        }
        with open(self.permission_file, 'w') as f:
            json.dump(permissions, f)
        
        # 设置全局配置
        self.config = {
            'git_repo_path': self.git_repo_path,
            'git_http_backend': self.backend_path,
            'log_dir': self.log_dir,
            'server_port': 8080
        }
        # 更新全局配置
        SERVER_CONFIG.update(self.config)
        
        # 设置 logger
        self.logger = logging.getLogger('test_logger')
        self.logger.addHandler(logging.NullHandler())

        # 创建一个更完善的 mock 请求
        class MockSocket:
            def __init__(self):
                self._rfile = BytesIO(b'GET / HTTP/1.1\r\n\r\n')
                self._wfile = BytesIO()

            def makefile(self, mode, bufsize):
                if 'r' in mode:
                    self._rfile.seek(0)
                    return self._rfile
                else:
                    return self._wfile

            def sendall(self, data):
                self._wfile.write(data)

            def close(self):
                self._rfile.close()
                self._wfile.close()

        # 设置测试请求环境
        self.request = MockSocket()
        self.client_address = ('127.0.0.1', 12345)
        self.server = MagicMock()
        
        # 创建一个更完善的MockGitHttpServer类
        class MockGitHttpServer(GitHttpServer):
            def __init__(self, *args, **kwargs):
                self.requestline = ""
                self.request_version = "HTTP/1.1"
                self.command = "GET"
                self.path = ""
                self.close_connection = False
                self.raw_requestline = b""
                self.rfile = BytesIO()
                self.wfile = BytesIO()
                self.headers = {}
                self._headers_buffer = []
                self.responses = {}  # 用于存储预定义的响应
                super().__init__(*args, **kwargs)

            def handle(self):
                pass  # 避免实际的请求处理
                
            def send_response(self, code, message=None):
                self.responses['code'] = code
                self.responses['message'] = message
                
            def send_header(self, keyword, value):
                self.responses[keyword] = value
                
            def end_headers(self):
                pass
                
            def log_request(self, code='-', size='-'):
                pass  # 避免实际的日志记录

        self.handler = MockGitHttpServer(self.request, self.client_address, self.server)
        self.handler.command = 'GET'
        self.handler.path = ''
        
    def tearDown(self):
        """每个测试用例执行后的清理"""
        # 删除临时测试目录
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_authenticate_success(self):
        """测试用户认证成功的情况"""
        # 设置认证头
        auth_string = base64.b64encode(b'alice:password123').decode()
        self.handler.headers = {'Authorization': f'Basic {auth_string}'}
        
        success, username = self.handler.authenticate()
        self.assertTrue(success)
        self.assertEqual(username, 'alice')
    
    def test_authenticate_failure_wrong_password(self):
        """测试密码错误的情况"""
        # 设置错误的认证头
        auth_string = base64.b64encode(b'alice:wrongpass').decode()
        self.handler.headers = {'Authorization': f'Basic {auth_string}'}
        
        success, username = self.handler.authenticate()
        self.assertFalse(success)
        self.assertIsNone(username)
    
    def test_authenticate_failure_no_auth_header(self):
        """测试没有认证头的情况"""
        self.handler.headers = {}
        success, username = self.handler.authenticate()
        self.assertFalse(success)
        self.assertIsNone(username)
    
    def test_get_repo_name(self):
        """测试仓库名称获取"""
        cases = [
            ('test-repo/info/refs', 'test-repo.git'),
            ('test-repo.git/info/refs', 'test-repo.git'),
            ('', None),
            ('invalid/path/with/no/repo', 'invalid.git')
        ]
        
        for input_path, expected_output in cases:
            self.assertEqual(
                self.handler._get_repo_name(input_path),
                expected_output
            )
    
    def test_check_repository(self):
        """测试仓库检查"""
        # 创建测试仓库
        test_repo_path = os.path.join(self.git_repo_path, 'test-repo.git')
        os.makedirs(test_repo_path)
        
        # 测试存在的仓库
        self.assertTrue(self.handler._check_repository('test-repo/info/refs'))
        
        # 测试不存在的仓库
        self.assertFalse(self.handler._check_repository('nonexistent-repo/info/refs'))
    
    def test_get_access_type(self):
        """测试访问类型检查"""
        # 测试读取请求
        self.assertEqual(
            self.handler._get_access_type('test-repo/git-upload-pack'),
            'read'
        )
        
        # 测试写入请求
        self.assertEqual(
            self.handler._get_access_type('test-repo/git-receive-pack'),
            'write'
        )
    
    def test_check_permission(self):
        """测试权限检查"""
        # 测试有写权限的用户
        self.assertTrue(self.handler.check_permission(
            'test-repo/info/refs', 'alice', 'write'))
        
        # 测试只有读权限的用户尝试写入
        self.assertFalse(self.handler.check_permission(
            'test-repo/info/refs', 'bob', 'write'))
        
        # 测试不存在的用户
        self.assertFalse(self.handler.check_permission(
            'test-repo/info/refs', 'charlie', 'read'))
    
    @patch('subprocess.Popen')
    def test_execute_git_backend(self, mock_popen):
        """测试 git-http-backend 执行"""
        # 模拟成功的进程执行
        mock_process = MagicMock()
        mock_process.communicate.return_value = (b'Status: 200 OK\r\n\r\nMock response', b'')
        mock_popen.return_value = mock_process
        
        # 设置请求环境
        env = {'GIT_PROJECT_ROOT': self.git_repo_path}
        self.handler.command = 'GET'
        self.handler._execute_git_backend(env)
        
        # 验证进程是否被正确调用
        mock_popen.assert_called_once_with(
            self.backend_path,
            env=env,
            stdout=unittest.mock.ANY,
            stdin=unittest.mock.ANY,
            stderr=unittest.mock.ANY,
            shell=False
        )

if __name__ == '__main__':
    unittest.main(verbosity=2)

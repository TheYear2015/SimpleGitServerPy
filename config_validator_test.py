import unittest
import os
import json
import logging
import shutil
import tempfile
from config_validator import ConfigValidator

class TestConfigValidator(unittest.TestCase):
    def setUp(self):
        """每个测试用例执行前的设置"""
        # 创建临时测试目录
        self.test_dir = tempfile.mkdtemp()
        self.git_repo_path = os.path.join(self.test_dir, 'repos')
        self.log_dir = os.path.join(self.test_dir, 'logs')
        
        # 创建测试用的 git-http-backend 文件
        self.backend_path = os.path.join(self.test_dir, 'git-http-backend')
        with open(self.backend_path, 'w') as f:
            f.write('#!/bin/sh\necho "Mock git-http-backend"')
        os.chmod(self.backend_path, 0o755)  # 设置可执行权限
        
        # 设置 logger
        self.logger = logging.getLogger('test_logger')
        self.logger.addHandler(logging.NullHandler())
    
    def tearDown(self):
        """每个测试用例执行后的清理"""
        # 删除临时测试目录
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_validate_config_with_required_keys(self):
        """测试包含所有必需键的配置验证"""
        config = {
            'git_repo_path': self.git_repo_path,
            'git_http_backend': self.backend_path,
            'log_dir': self.log_dir
        }
        validated = ConfigValidator.validate_config(config, self.logger)
        
        # 验证必需的键是否正确保存
        self.assertEqual(validated['git_repo_path'], self.git_repo_path)
        self.assertEqual(validated['git_http_backend'], self.backend_path)
        self.assertEqual(validated['log_dir'], self.log_dir)
    
    def test_validate_config_missing_required_key(self):
        """测试缺少必需键时的错误处理"""
        config = {
            'git_repo_path': self.git_repo_path,
            # 缺少 git_http_backend
            'log_dir': self.log_dir
        }
        with self.assertRaises(KeyError) as context:
            ConfigValidator.validate_config(config, self.logger)
        self.assertEqual(str(context.exception), "'Missing required configuration key: git_http_backend'")
    
    def test_validate_config_with_default_values(self):
        """测试默认值设置"""
        config = {
            'git_repo_path': self.git_repo_path,
            'git_http_backend': self.backend_path,
            'log_dir': self.log_dir
        }
        validated = ConfigValidator.validate_config(config, self.logger)
        
        # 验证默认值
        self.assertEqual(validated['server_port'], 8000)
        self.assertEqual(validated['max_request_size'], 1024 * 1024 * 100)
        self.assertEqual(validated['session_timeout'], 3600)
        self.assertEqual(validated['max_auth_attempts'], 3)
    
    def test_validate_paths_with_nonexistent_dirs(self):
        """测试不存在的目录自动创建"""
        config = {
            'git_repo_path': os.path.join(self.test_dir, 'new_repos'),
            'git_http_backend': self.backend_path,
            'log_dir': os.path.join(self.test_dir, 'new_logs')
        }
        validated = ConfigValidator.validate_config(config, self.logger)
        
        # 验证目录是否被创建
        self.assertTrue(os.path.exists(config['git_repo_path']))
        self.assertTrue(os.path.exists(config['log_dir']))
    
    def test_validate_paths_with_invalid_backend(self):
        """测试无效的 git-http-backend 路径处理"""
        config = {
            'git_repo_path': self.git_repo_path,
            'git_http_backend': os.path.join(self.test_dir, 'nonexistent-backend'),
            'log_dir': self.log_dir
        }
        with self.assertRaises(ValueError) as context:
            ConfigValidator.validate_config(config, self.logger)
        self.assertTrue("git-http-backend not found at:" in str(context.exception))
    
    def test_validate_config_with_custom_values(self):
        """测试自定义值覆盖默认值"""
        config = {
            'git_repo_path': self.git_repo_path,
            'git_http_backend': self.backend_path,
            'log_dir': self.log_dir,
            'server_port': 8080,
            'max_request_size': 2048
        }
        validated = ConfigValidator.validate_config(config, self.logger)
        
        # 验证自定义值
        self.assertEqual(validated['server_port'], 8080)
        self.assertEqual(validated['max_request_size'], 2048)
        # 验证其他默认值保持不变
        self.assertEqual(validated['session_timeout'], 3600)
        self.assertEqual(validated['max_auth_attempts'], 3)

if __name__ == '__main__':
    unittest.main(verbosity=2)

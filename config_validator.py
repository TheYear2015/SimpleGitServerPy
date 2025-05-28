import os
import logging
from typing import Dict, Any

class ConfigValidator:
    """Git HTTP Server 的配置验证器"""
    
    # 必需的配置键
    REQUIRED_KEYS = ['git_repo_path', 'git_http_backend', 'log_dir']
    # 默认配置
    DEFAULT_CONFIG = {
        'server_port': 8000,
        'log_dir': None,  # 将被设置为 os.path.join(os.getcwd(), 'logs')
        'max_request_size': 1024 * 1024 * 100,  # 100 MB
        'session_timeout': 3600,  # 1 小时
        'max_auth_attempts': 3
    }
    
    @staticmethod
    def validate_config(config: Dict[str, Any], logger: logging.Logger) -> Dict[str, Any]:
        """验证配置并设置默认值"""
        # 验证必需的键
        for key in ConfigValidator.REQUIRED_KEYS:
            if key not in config:
                raise KeyError(f"Missing required configuration key: {key}")
                
        # 为可选键设置默认值
        validated_config = config.copy()
        for key, default_value in ConfigValidator.DEFAULT_CONFIG.items():
            if key not in validated_config:
                if key == 'log_dir' and default_value is None:
                    validated_config[key] = os.path.join(os.getcwd(), 'logs')
                else:
                    validated_config[key] = default_value
                    
        # 验证路径
        ConfigValidator._validate_paths(validated_config, logger)
                    
        return validated_config
    
    @staticmethod
    def _validate_paths(config: Dict[str, Any], logger: logging.Logger) -> None:
        """验证所有路径配置"""
        # 验证 git_repo_path
        if not os.path.exists(config['git_repo_path']):
            try:
                os.makedirs(config['git_repo_path'])
                logger.info(f"Created repository directory: {config['git_repo_path']}")
            except OSError as e:
                raise ValueError(f"Cannot create repository directory: {e}")
                
        # 验证 git_http_backend
        backend_path = config['git_http_backend']
        if not os.path.exists(backend_path):
            raise ValueError(f"git-http-backend not found at: {backend_path}")
        if not os.path.isfile(backend_path):
            raise ValueError(f"git-http-backend path is not a file: {backend_path}")
        if not os.access(backend_path, os.X_OK):
            raise ValueError(f"git-http-backend is not executable: {backend_path}")
            
        # 验证并创建日志目录
        os.makedirs(config['log_dir'], exist_ok=True)

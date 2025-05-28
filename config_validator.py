import os
import logging
from typing import Dict, Any

class ConfigValidator:
    """Configuration validator for Git HTTP Server"""
    
    REQUIRED_KEYS = ['git_repo_path', 'git_http_backend', 'log_dir']
    DEFAULT_CONFIG = {
        'server_port': 8000,
        'log_dir': None,  # Will be set to os.path.join(os.getcwd(), 'logs')
        'max_request_size': 1024 * 1024 * 100,  # 100MB
        'session_timeout': 3600,  # 1 hour
        'max_auth_attempts': 3
    }
    
    @staticmethod
    def validate_config(config: Dict[str, Any], logger: logging.Logger) -> Dict[str, Any]:
        """Validate configuration and set defaults"""
        # Verify required keys
        for key in ConfigValidator.REQUIRED_KEYS:
            if key not in config:
                raise KeyError(f"Missing required configuration key: {key}")
                
        # Set defaults for optional keys
        validated_config = config.copy()
        for key, default_value in ConfigValidator.DEFAULT_CONFIG.items():
            if key not in validated_config:
                if key == 'log_dir' and default_value is None:
                    validated_config[key] = os.path.join(os.getcwd(), 'logs')
                else:
                    validated_config[key] = default_value
                    
        # Validate paths
        ConfigValidator._validate_paths(validated_config, logger)
                    
        return validated_config
    
    @staticmethod
    def _validate_paths(config: Dict[str, Any], logger: logging.Logger) -> None:
        """Validate all path configurations"""
        # Validate git_repo_path
        if not os.path.exists(config['git_repo_path']):
            try:
                os.makedirs(config['git_repo_path'])
                logger.info(f"Created repository directory: {config['git_repo_path']}")
            except OSError as e:
                raise ValueError(f"Cannot create repository directory: {e}")
                
        # Validate git_http_backend
        backend_path = config['git_http_backend']
        if not os.path.exists(backend_path):
            raise ValueError(f"git-http-backend not found at: {backend_path}")
        if not os.path.isfile(backend_path):
            raise ValueError(f"git-http-backend path is not a file: {backend_path}")
        if not os.access(backend_path, os.X_OK):
            raise ValueError(f"git-http-backend is not executable: {backend_path}")
            
        # Validate and create log directory
        os.makedirs(config['log_dir'], exist_ok=True)

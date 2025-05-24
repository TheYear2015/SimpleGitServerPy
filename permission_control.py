import json

class PermissionControl:
    def __init__(self, permission_file):
        print("初始化权限控制")  # 调试日志
        self.permission_file = permission_file
        self.permissions = self.load_permissions()
        print("已加载权限:", self.permissions)  # 调试日志
    
    def load_permissions(self):
        """从文件加载权限配置"""
        try:
            with open(self.permission_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
    
    def check_permission(self, repo_name, username, access_type):
        """
        检查用户是否有仓库的指定权限
        :param repo_name: 仓库名称
        :param username: 用户名
        :param access_type: 权限类型 ('read' or 'write')
        :return: bool
        """
        if repo_name not in self.permissions:
            return False
        
        repo_permissions = self.permissions[repo_name]
        if username not in repo_permissions:
            return False
            
        user_perms = repo_permissions[username]
        # 检查权限
        if access_type == 'read':
            return 'r' in user_perms
        elif access_type == 'write':
            return 'w' in user_perms
            
        return False
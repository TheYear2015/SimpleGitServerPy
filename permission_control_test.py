import unittest
import json
import os
from permission_control import PermissionControl

class TestPermissionControl(unittest.TestCase):
    def setUp(self):
        """每个测试用例执行前的设置"""
        # 创建测试用的权限文件
        self.test_permission_file = 'test_permissions.json'
        self.test_permissions = {
            'test-repo.git': {
                'alice': 'rw',
                'bob': 'r',
                'charlie': 'w'
            },
            'another-repo.git': {
                'alice': 'r',
                'bob': 'rw'
            }
        }
        with open(self.test_permission_file, 'w') as f:
            json.dump(self.test_permissions, f)
        
        # 初始化 PermissionControl 实例
        self.permission_control = PermissionControl(self.test_permission_file)
    
    def tearDown(self):
        """每个测试用例执行后的清理"""
        # 删除测试用的权限文件
        if os.path.exists(self.test_permission_file):
            os.remove(self.test_permission_file)
    
    def test_load_permissions(self):
        """测试权限加载功能"""
        # 测试正常加载
        self.assertEqual(self.permission_control.permissions, self.test_permissions)
        
        # 测试文件不存在的情况
        non_existent_file = 'non_existent.json'
        pc = PermissionControl(non_existent_file)
        self.assertEqual(pc.permissions, {})
    
    def test_check_permission_read(self):
        """测试读权限检查"""
        # 测试有读权限的用户
        self.assertTrue(self.permission_control.check_permission(
            'test-repo.git', 'alice', 'read'))
        self.assertTrue(self.permission_control.check_permission(
            'test-repo.git', 'bob', 'read'))
        
        # 测试没有读权限的用户
        self.assertFalse(self.permission_control.check_permission(
            'test-repo.git', 'charlie', 'read'))
        
        # 测试不存在的用户
        self.assertFalse(self.permission_control.check_permission(
            'test-repo.git', 'david', 'read'))
    
    def test_check_permission_write(self):
        """测试写权限检查"""
        # 测试有写权限的用户
        self.assertTrue(self.permission_control.check_permission(
            'test-repo.git', 'alice', 'write'))
        self.assertTrue(self.permission_control.check_permission(
            'test-repo.git', 'charlie', 'write'))
        
        # 测试没有写权限的用户
        self.assertFalse(self.permission_control.check_permission(
            'test-repo.git', 'bob', 'write'))
        
        # 测试不存在的用户
        self.assertFalse(self.permission_control.check_permission(
            'test-repo.git', 'david', 'write'))
    
    def test_non_existent_repo(self):
        """测试不存在的仓库"""
        self.assertFalse(self.permission_control.check_permission(
            'non-existent-repo.git', 'alice', 'read'))
        self.assertFalse(self.permission_control.check_permission(
            'non-existent-repo.git', 'alice', 'write'))
    
    def test_invalid_access_type(self):
        """测试无效的访问类型"""
        self.assertFalse(self.permission_control.check_permission(
            'test-repo.git', 'alice', 'invalid'))

if __name__ == '__main__':
    unittest.main()

import inspect
import importlib
import pkgutil
import logging
from typing import List, Type
from plugins.core.base import BaseScanner

logger = logging.getLogger("das_sentinel.scanner_registry")

class ScannerRegistry:
    """
    通用插件注册表 (Scanner Registry)
    支持多层级包结构递归自动发现 (walk_packages) 与无缝动态注册。
    无论插件在 plugins/scanner_core 还是 plugins/scanner_extensions/* 任意深度子目录中，
    均可自动发现并无缝装载，实现彻底的零侵入解耦。
    """
    def __init__(self):
        self._scanners: List[Type[BaseScanner]] = []

    def register(self, scanner_cls: Type[BaseScanner]):
        if scanner_cls not in self._scanners:
            self._scanners.append(scanner_cls)
            logger.info(f"Registered scanner plugin: {scanner_cls.__name__} from {scanner_cls.__module__}")

    def discover_scanners(self, package_names: List[str]):
        """Dynamically load and register all subclasses of BaseScanner in given packages, recursively."""
        for package_name in package_names:
            try:
                package = importlib.import_module(package_name)
                # 首先检查直接包模块
                for name, obj in inspect.getmembers(package, inspect.isclass):
                    if issubclass(obj, BaseScanner) and obj is not BaseScanner:
                        self.register(obj)

                # 递归遍历所有子包和模块
                if hasattr(package, "__path__"):
                    prefix = package.__name__ + "."
                    for _, module_name, is_pkg in pkgutil.walk_packages(package.__path__, prefix):
                        try:
                            module = importlib.import_module(module_name)
                            for name, obj in inspect.getmembers(module, inspect.isclass):
                                if issubclass(obj, BaseScanner) and obj is not BaseScanner:
                                    self.register(obj)
                        except Exception as mod_err:
                            logger.warning(f"Could not load module {module_name}: {mod_err}")
            except Exception as e:
                logger.error(f"Failed to discover scanners in package {package_name}: {e}")

    def get_all_scanners(self) -> List[Type[BaseScanner]]:
        return self._scanners

    def get_scanner_by_name(self, name: str) -> Type[BaseScanner] | None:
        for scanner in self._scanners:
            if scanner.__name__ == name:
                return scanner
        return None

# 全局注册表单例
scanner_registry = ScannerRegistry()

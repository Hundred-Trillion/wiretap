import pytest
from wiretap.plugins.registry import PluginRegistry
from wiretap.plugins.generic import GenericPlugin

def test_plugin_registry_registration():
    reg = PluginRegistry()
    plugin = GenericPlugin()
    
    reg.register(plugin)
    assert plugin in reg.plugins
    
    info_list = reg.list_info()
    assert len(info_list) == 1
    assert info_list[0].name == "generic"

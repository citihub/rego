import os

from jinja2 import Environment, FileSystemLoader

env = Environment(
    loader=FileSystemLoader(os.path.join(os.getcwd()))
)

template = env.get_template("name_length.rego.j2")

print(template.render(name_length_limits=[
    {
        "terraform_resource_name": "azurerm_windows_virtual_machine",
        "max_length": 64,
    },
    {
        "terraform_resource_name": "azurerm_linux_virtual_machine",
        "max_length": 64,
    },
    {
        "terraform_resource_name": "azurerm_linux_virtual_machine",
        "terraform_field_name": "computer_name",
        "max_length": 64,
    },
    {
        "terraform_resource_name": "azurerm_windows_virtual_machine",
        "terraform_field_name": "computer_name",
        "max_length": 15,
    },
    {
        "terraform_resource_name": "azurerm_automation_account",
        "max_length": 50,
    },
    {
        "terraform_resource_name": "azurerm_automation_schedule",
        "max_length": 128,
    },
    {
        "terraform_resource_name": "azurerm_shared_image_gallery",
        "max_length": 80,
    },
    {
        "terraform_resource_name": "azurerm_user_assigned_identity",
        "max_length": 128,
    },
    {
        "terraform_resource_name": "azurerm_resource_group",
        "max_length": 90,
    },
    {
        "terraform_resource_name": "azurerm_storage_account",
        "max_length": 24,
    },
    {
        "terraform_resource_name": "azurerm_storage_container",
        "max_length": 63,
    },
    {
        "terraform_resource_name": "azurerm_key_vault",
        "max_length": 24,
    },
    {
        "terraform_resource_name": "azurerm_private_dns_zone",
        "max_length": 63,
    },
    {
        "terraform_resource_name": "azurerm_private_dns_zone_virtual_network_link",
        "max_length": 80,
    },
]))
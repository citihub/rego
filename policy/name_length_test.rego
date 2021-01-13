package main

test_legit_dns_zone_link_limit {
    no_violations with input as {
        "resource_changes": [{
            "type": "azurerm_private_dns_zone_virtual_network_link",
            "change": {
                "after": {
                    "name": "app.uksouth.azure.nonprod.zone--app-uksouth-nonprod-vnet-link"
                }
            }
        }]
    }
}

test_illegit_dns_zone_link_limit {
    deny[`azurerm_private_dns_zone_virtual_network_link limit is 80 characters, found 1 violation(s) (myapplication.uksouth.azure.nonprod.private.zone--app-uksouth-nonprod-virtualnetwork-link)`] with input as {
        "resource_changes": [{
            "type": "azurerm_private_dns_zone_virtual_network_link",
            "change": {
                "after": {
                    "name": "myapplication.uksouth.azure.nonprod.private.zone--app-uksouth-nonprod-virtualnetwork-link"
                }
            }
        }]
    }
}

test_legit_virtual_machine_name_limit {
    no_violations with input as {
        "resource_changes": [{
            "type": "azurerm_windows_virtual_machine",
            "change": {
                "after": {
                    "name": "AZURE-UKSOUTH-SHARED-DEV-APP-VM",
                    "computer_name": "AZUUKSDEVAPPVM"
                }
            }
        }]
    }
}

test_illegit_virtual_machine_name_limit {
    deny[`azurerm_windows_virtual_machine limit is 15 characters, found 1 violation(s) (AZUREUKSOUTHSHAREDDEVAPPVM)`] with input as {
        "resource_changes": [{
            "type": "azurerm_windows_virtual_machine",
            "change": {
                "after": {
                    "name": "AZURE-UKSOUTH-SHARED-DEV-APP-VM",
                    "computer_name": "AZUREUKSOUTHSHAREDDEVAPPVM"
                }
            }
        }]
    }
}

test_illegit_virtual_machine_name_limit {
    no_violations with input as {
        "resource_changes": [{
            "type": "azurerm_windows_virtual_machine",
            "change": {
                "after": null
            }
        }]
    }
}

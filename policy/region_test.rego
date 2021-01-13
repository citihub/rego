package main

test_illegit_region {
    deny["Expected all resources to be in a supported region, but 1 were not (voluptate-hic-eos-ea-magni-et)"] with input as {
        "resource_changes": [{
            "type": "azurerm_resource_group",
            "change": {
                "after": {
                    "name": "voluptate-hic-eos-ea-magni-et",
                    "location": "ukwest",
                }
            }
        }]
    }
}

test_legit_region {
    no_violations with input as {
        "resource_changes": [{
            "type": "azurerm_resource_group",
            "change": {
                "after": {
                    "name": "voluptate-hic-eos-ea-magni-et",
                    "location": "uksouth",
                }
            }
        }]
    }
}

test_ignore_regionless_resource {
    no_violations with input as {
        "resource_changes": [{
            "type": "azurerm_policy_assignment",
            "change": {
                "after": {
                    "name": "append-tag-created-by",
                    "location": null,
                }
            }
        }]
    }
}
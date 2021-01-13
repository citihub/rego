package main

test_missing_tags_taggable_resource {
    deny["Expected 0 untagged resources but found 1"] with input as {
        "resource_changes": [{
            "type": "azurerm_resource_group",
            "change": {
                "after": {
                    "name": "voluptate-hic-eos-ea-magni-et",
                    "location": "ukwest",
                    "tags": {}
                }
            }
        }]
    }
}

test_no_violation_untaggable_resource {
    no_violations with input as {
        "resource_changes": [{
            "type": "azurerm_key_vault_secret",
            "change": {
                "after": {
                    "name": "lorem",
                    "value": "ipsum",
                    "tags": null
                }
            }
        }]
    }
}

test_no_violation_untaggable_resource_2 {
    no_violations with input as {
        "resource_changes": [{
            "type": "azurerm_key_vault_secret",
            "change": {
                "after": {
                    "name": "lorem",
                    "value": "ipsum",
                }
            }
        }]
    }
}

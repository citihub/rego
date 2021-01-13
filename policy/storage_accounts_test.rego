package main

test_well_configured_storage_account {
    no_violations with input as {
        "resource_changes": [{
            "type": "azurerm_storage_account",
            "change": {
                "after": {
                    "location": "uksouth",
                    "name": "aperiamhicetad",
                    "resource_group_name": "voluptate-hic-eos-ea-magni-et",
                    "allow_blob_public_access": false,
                    "enable_https_traffic_only": true,
                    "min_tls_version": "TLS1_2",
                }
            }
        }]
    }
}

test_storage_account_https_only {
    deny[`Expected every Storage Account to be accessible over HTTPS only, but 1 were not`] with input as {
        "resource_changes": [{
            "type": "azurerm_storage_account",
            "change": {
                "after": {
                    "location": "uksouth",
                    "name": "aperiamhicetad",
                    "resource_group_name": "voluptate-hic-eos-ea-magni-et",
                    "allow_blob_public_access": false,
                    "enable_https_traffic_only": false,
                    "min_tls_version": "TLS1_2",
                }
            }
        }]
    }
}

test_storage_account_public_access {
    deny[`Expected every Storage Account to prevent public access, but 1 were not`] with input as {
        "resource_changes": [{
            "type": "azurerm_storage_account",
            "change": {
                "after": {
                    "location": "uksouth",
                    "name": "aperiamhicetad",
                    "resource_group_name": "voluptate-hic-eos-ea-magni-et",
                    "allow_blob_public_access": true,
                    "enable_https_traffic_only": true,
                    "min_tls_version": "TLS1_2",
                }
            }
        }]
    }
}

test_storage_account_tls_version {
    deny[`Expected every Storage Account to require TLS 1.2, but 1 were not`] with input as {
        "resource_changes": [{
            "type": "azurerm_storage_account",
            "change": {
                "after": {
                    "location": "uksouth",
                    "name": "aperiamhicetad",
                    "resource_group_name": "voluptate-hic-eos-ea-magni-et",
                    "allow_blob_public_access": false,
                    "enable_https_traffic_only": true,
                    "min_tls_version": "TLS1_0",
                }
            }
        }]
    }
}
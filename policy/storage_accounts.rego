package main

storage_accounts := [ resource |
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
]

# Storage Accounts must not be accessible over HTTP
deny[msg] {
    expected := 0
    actual := count([res | res := storage_accounts[_]; not res.change.after.enable_https_traffic_only])
    expected != actual
    msg := sprintf("Expected every Storage Account to be accessible over HTTPS only, but %v were not", [actual])
}

# Storage Accounts must enforce TLS 1.2
deny[msg] {
    expected := 0
    actual := count([res | res := storage_accounts[_]; not res.change.after.min_tls_version == "TLS1_2"])
    expected != actual
    msg := sprintf("Expected every Storage Account to require TLS 1.2, but %v were not", [actual])
}

# Storage Accounts must not allow public access
deny[msg] {
    expected := 0
    actual := count([res | res := storage_accounts[_]; res.change.after.allow_blob_public_access])
    expected != actual
    msg := sprintf("Expected every Storage Account to prevent public access, but %v were not", [actual])
}

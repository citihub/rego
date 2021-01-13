package main

name_length(resource_type, length_limit, field_name, default_field_name) = actual {

    resources := [ resource |
        resource := input.resource_changes[_]
        resource.type == resource_type
    ]

    actual := [object.get(rg.change.after, field_name, object.get(rg.change.after, default_field_name, null)) |
        rg := resources[_];
        not is_null(rg.change.after);
        count(object.get(rg.change.after, field_name, object.get(rg.change.after, default_field_name, null))) > length_limit
    ]
}



# Validate azurerm_windows_virtual_machine name length
deny[msg] {
    actual := name_length("azurerm_windows_virtual_machine", 64, "name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_windows_virtual_machine limit is 64 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_linux_virtual_machine name length
deny[msg] {
    actual := name_length("azurerm_linux_virtual_machine", 64, "name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_linux_virtual_machine limit is 64 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_linux_virtual_machine name length
deny[msg] {
    actual := name_length("azurerm_linux_virtual_machine", 64, "computer_name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_linux_virtual_machine limit is 64 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_windows_virtual_machine name length
deny[msg] {
    actual := name_length("azurerm_windows_virtual_machine", 15, "computer_name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_windows_virtual_machine limit is 15 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_automation_account name length
deny[msg] {
    actual := name_length("azurerm_automation_account", 50, "name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_automation_account limit is 50 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_automation_schedule name length
deny[msg] {
    actual := name_length("azurerm_automation_schedule", 128, "name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_automation_schedule limit is 128 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_shared_image_gallery name length
deny[msg] {
    actual := name_length("azurerm_shared_image_gallery", 80, "name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_shared_image_gallery limit is 80 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_user_assigned_identity name length
deny[msg] {
    actual := name_length("azurerm_user_assigned_identity", 128, "name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_user_assigned_identity limit is 128 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_resource_group name length
deny[msg] {
    actual := name_length("azurerm_resource_group", 90, "name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_resource_group limit is 90 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_storage_account name length
deny[msg] {
    actual := name_length("azurerm_storage_account", 24, "name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_storage_account limit is 24 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_storage_container name length
deny[msg] {
    actual := name_length("azurerm_storage_container", 63, "name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_storage_container limit is 63 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_key_vault name length
deny[msg] {
    actual := name_length("azurerm_key_vault", 24, "name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_key_vault limit is 24 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_private_dns_zone name length
deny[msg] {
    actual := name_length("azurerm_private_dns_zone", 63, "name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_private_dns_zone limit is 63 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}

# Validate azurerm_private_dns_zone_virtual_network_link name length
deny[msg] {
    actual := name_length("azurerm_private_dns_zone_virtual_network_link", 80, "name", "name")
    0 != count(actual)
    msg = sprintf("azurerm_private_dns_zone_virtual_network_link limit is 80 characters, found %v violation(s) (%v)", [count(actual), concat(",", actual)])
}



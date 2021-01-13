package main

deny[msg] {
    expected := 0
    actual := [ res.change.after.name |
        res := resource_changes[_]
        # We exclude Policy Assignments because they don't have a location - the plan JSON has location=null
        not res.type == "azurerm_policy_assignment"
        not res.change.after == null
        not object.get(res.change.after, "location", "uksouth") == "uksouth"
    ]

    expected != count(actual)
    msg := sprintf("Expected all resources to be in a supported region, but %v were not (%v)", [count(actual), concat(",", actual)])
}
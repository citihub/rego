package main

test_enabled_kube_dashboard {
    deny["kubernetes dashboard should be disabled"] with input as {
        "resource_changes": [{
            "type": "azurerm_kubernetes_cluster",
            "change": {
                "after": {
                    "addon_profile": [
                        {
                            "kube_dashboard": [ {"enabled": true} ],
                        }
                    ]
                }
            }
        }]
    }
}

test_disabled_kube_dashboard {
    no_violations with input as {
        "resource_changes": [{
            "type": "azurerm_kubernetes_cluster",
            "change": {
                "after": {
                    "addon_profile": [
                        {
                            "kube_dashboard": [ {"enabled": false} ],
                        }
                    ]
                }
            }
        }]
    }
}

test_kube_dashboard_not_set {
    no_violations with input as {
        "resource_changes": [{
            "type": "azurerm_kubernetes_cluster",
            "change": {
                "after": {
                    "addon_profile": []
                }
            }
        }]
    }
}

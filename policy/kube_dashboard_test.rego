package main

test_enabled_kube_dashboard {
    deny["kubernetes dashboard should be disabled"] with input as {
        "resource_changes": [{
            "type": "azurerm_kubernetes_cluster",
            "change": {
                "after": {
                    "name": "my-cluster",
                    "addon_profile": [
                        {
                            "kube_dashboard": [ {"enabled": true} ]
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
                    "name": "my-cluster",
                    "addon_profile": [
                        {
                            "kube_dashboard": [ {"enabled": false} ]
                        }
                    ]
                }
            }
        }]
    }
}

test_no_addon_profile_at_all {
    deny["kubernetes dashboard should be explicitly disabled"] with input as {
        "resource_changes": [{
            "type": "azurerm_kubernetes_cluster",
            "change": {
                "after": {
                    "name": "my-cluster"
                }
            }
        }]
    }
}

test_no_kube_dashboard_addon_profile {
    deny["kubernetes dashboard should be explicitly disabled"] with input as {
        "resource_changes": [{
            "type": "azurerm_kubernetes_cluster",
            "change": {
                "after": {
                    "name": "my-cluster",
                    "addon_profile": []
                }
            }
        }]
    }
}

test_no_kube_dashboard_enabled_setting {
    deny["kubernetes dashboard should be explicitly disabled"] with input as {
        "resource_changes": [{
            "type": "azurerm_kubernetes_cluster",
            "change": {
                "after": {
                    "name": "my-cluster",
                    "addon_profile": [
                        {
                            "kube_dashboard": {
                                "lorem": "ipsum"
                            }
                        }
                    ]
                }
            }
        }]
    }
}

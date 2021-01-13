package main

azurerm_kubernetes_clusters := [resource |
    resource := input.resource_changes[_]
    resource.type == "azurerm_kubernetes_cluster"
]

deny[msg] {
    violations := count([res |
       res := azurerm_kubernetes_clusters[_];
       kdb := object.get( res.change.after.addon_profile[0], "kube_dashboard", [ {"enabled": false} ] )
       kdb[0].enabled
    ])
    violations > 0
    msg := "kubernetes dashboard should be disabled"
}

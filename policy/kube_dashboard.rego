package main

azurerm_kubernetes_clusters := [resource |
    resource := input.resource_changes[_]
    resource.type == "azurerm_kubernetes_cluster"
]

deny[msg] {
    violations := count([res |
       res := azurerm_kubernetes_clusters[_];
       kdb := object.get( res.change.after.addon_profile[0], "kube_dashboard", [{}] )
       kdb[0].enabled
    ])
    violations > 0
    msg := "kubernetes dashboard should be disabled"
}


is_kube_dashboard_explictly_disabled(x) = true {
	aop := object.get(x, "addon_profile", [])
    count(aop) > 0
    kdb := object.get(aop[0], "kube_dashboard", [])
    count(kdb) > 0
    enabled := object.get(kdb[0], "enabled", null)
    not enabled
    not enabled == null
}

deny[msg] {
    unset_violations := count([res |
        res := azurerm_kubernetes_clusters[_];
        not is_kube_dashboard_explictly_disabled
       (res.change.after)
    ])
    unset_violations > 0
    msg := "kubernetes dashboard should be explicitly disabled"
}

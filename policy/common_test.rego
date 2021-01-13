package main

test_input_with_no_change {
    no_violations with input as {
        "resource_changes": [{
            "type": "null_resource",
            "change": {
                "after": {}
            }
        }]
    }
}

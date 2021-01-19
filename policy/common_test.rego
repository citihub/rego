package main

test_blank_input {
    no_violations with input as {}
}

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

package main

resource_changes := [ resource |
    resource := input.resource_changes[_]
]

# Every taggable resource must be tagged
deny[msg] {
    violations := [res.change.after.name |
        res := resource_changes[_];
        res.change.after.tags == {}
    ]
    count(violations) > 0
    msg := sprintf("Expected 0 untagged resources but found %v", [count(violations)])
}

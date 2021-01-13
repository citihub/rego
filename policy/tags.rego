package main

resource_changes := [ resource |
    resource := input.resource_changes[_]
]

# Every taggable resource must be tagged
deny[msg] {
    expected := 0
    actual := [res.change.after.name |
        res := resource_changes[_];
        res.change.after.tags == {}
    ]
    expected != count(actual)
    msg := sprintf("Expected %v untagged resources but found %v", [expected, count(actual)])
}

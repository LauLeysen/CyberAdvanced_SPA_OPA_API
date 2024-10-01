package barmanagement

import future.keywords

test_allow_customer {
    input := {
        "jwt": {
            "role": ["customer"],
            "age": "34",
            "email": "customer@example.com",
            "email_verified": true
        }
    }
    allow with input as input
}

test_allow_bartender {
    input := {
        "jwt": {
            "role": ["bartender"],
            "age": "30",
            "email": "bartender@example.com",
            "email_verified": true
        }
    }
    allow with input as input
}

test_deny_guest {
    input := {
        "jwt": {
            "role": ["guest"],
            "age": "25",
            "email": "guest@example.com",
            "email_verified": false
        }
    }
    not allow with input as input
}

test_allow_multiple_roles {
    input := {
        "jwt": {
            "role": ["customer", "admin"],
            "age": "40",
            "email": "admincustomer@example.com",
            "email_verified": true
        }
    }
    allow with input as input
}

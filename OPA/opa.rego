package barmanagement

default allow = false

allow {
    order_drink
}

allow {
    order_beer
}

allow {
    manage_bar
}

order_drink {
    is_authorized("customer", "child")
    input.request.method == "POST"
    input.request.path == "/api/bar"
    input.request.body.DrinkName == "Fristi"
}

order_beer {
    is_authorized("customer", "adult")
    input.request.method == "POST"
    input.request.path == "/api/bar"
    input.request.body.DrinkName == "Beer"
}

manage_bar {
    is_authorized("bartender", "adult")
    input.request.method == "POST"
    input.request.path == "/api/managebar"
}

is_authorized(required_role, drinktype) {
    token := jwt_decode(input.request.headers.Authorization)
    user_role := token[1].role

    some i
    user_role[i] == required_role

    drinktype == "child"
}

is_authorized(required_role, drinktype) {
    token := jwt_decode(input.request.headers.Authorization)
    user_age := to_number(token[1].age)
    user_role := token[1].role

    some i
    user_role[i] == required_role

    drinktype == "adult"
    user_age >= 16
}

jwt_decode(token) = decoded_token {
    parts := split(token, " ")
    count(parts) == 2
    jwt := parts[1]  # Extract the actual JWT part after 'Bearer'
    [header, payload, signature] := io.jwt.decode(jwt)
    decoded_token := [header, payload, signature]
}
// The wallet presentation protocol answers only a closed read request: a
// session reference and the principal that created the session. No credential
// value, token or selector other than those three strings enters this script.
fn read_request(exchange) {
    #{
        reference: exchange.body.reference,
        principal: #{
            issuer: exchange.body.principalIssuer,
            subject: exchange.body.principalSubject
        }
    }
}

// The protocol has already verified the credential. A possession-only route
// keeps nothing the holder disclosed.
fn possession(exchange) {
    if exchange.body.lookup != "matched" { throw "wallet-lookup-contract"; }
    #{lookup: "matched", facts: #{presented: true}}
}

// An identity route keeps the one disclosed name for the derivation to compare.
fn identity(exchange) {
    if exchange.body.lookup != "matched" { throw "wallet-lookup-contract"; }
    let name = exchange.body.values.name;
    if name.type_of() != "string" { throw "wallet-name-contract"; }
    #{lookup: "matched", facts: #{name: name}}
}

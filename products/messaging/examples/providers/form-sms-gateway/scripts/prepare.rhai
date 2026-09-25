// Shape one SMS as the provider's form POST. Rust form-encodes the body and
// adds the Basic credential after this returns.
fn prepare(message, profile) {
    if message.channel != "sms" {
        throw "this provider carries sms only";
    }
    #{
        target: "Messages.json",
        bodyFormat: "form",
        body: #{
            To: message.recipient,
            From: profile.sender,
            Body: message.parts.text,
        },
    }
}

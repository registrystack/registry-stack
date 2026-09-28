// Shape one message as a JSON POST. The idempotency key is stable across
// every attempt of one message, so the gateway can drop a repeat.
fn prepare(message, profile) {
    let body = #{
        channel: message.channel,
        to: message.recipient,
        from: profile.sender,
        text: message.parts.text,
    };
    if message.parts.subject != () {
        body.subject = message.parts.subject;
    }
    if message.parts.html != () {
        body.html = message.parts.html;
    }
    let headers = #{ "x-request-id": message.messageId };
    if message.idempotencyKey != () {
        headers["idempotency-key"] = message.idempotencyKey;
    }
    #{ target: "messages", headers: headers, bodyFormat: "json", body: body }
}

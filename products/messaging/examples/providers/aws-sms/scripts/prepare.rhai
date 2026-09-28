// Shape one SMS as AWS End User Messaging SMS SendTextMessage. Rust encodes
// the body as AWS JSON 1.0 and signs the exact request after this returns.
fn prepare(message, profile) {
    if message.channel != "sms" {
        throw "this provider carries sms only";
    }

    let body = #{
        DestinationPhoneNumber: message.recipient,
        OriginationIdentity: profile.sender,
        MessageBody: message.parts.text,
        MessageType: "TRANSACTIONAL",
    };

    // Operator settings. Leave these defaults to omit the optional members,
    // or replace them in the reviewed package with deployment-specific values.
    let configuration_set_name = ""; // for example, "registry-messages"
    let maximum_price_usd = "";       // for example, "0.05"
    let time_to_live_seconds = 0;      // 5 to 259200
    if configuration_set_name != "" {
        body.ConfigurationSetName = configuration_set_name;
    }
    if maximum_price_usd != "" {
        body.MaxPrice = maximum_price_usd;
    }
    if time_to_live_seconds != 0 {
        body.TimeToLive = time_to_live_seconds;
    }

    #{
        target: "",
        headers: #{
            "x-amz-target": "PinpointSMSVoiceV2.SendTextMessage",
        },
        bodyFormat: "json",
        body: body,
    }
}


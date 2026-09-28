// AWS documents HTTP 200 with MessageId as accepted. There is no provider
// idempotency token, so an unreadable success, an unexpected answer, or a 5xx
// is maybe-sent rather than retryable. Only the documented throttle is safe to
// retry, and documented terminal exception names become bounded local codes.
// AWS refuses an unauthenticated or badly signed request before the service
// acts on it, so those names are terminal too. An expired session token is
// terminal because an explicit secret reference is never refreshed.
fn interpret(response) {
    let body = response.body;
    let is_map = type_of(body) == "map";

    if response.status == 200 {
        if is_map && type_of(body.MessageId) == "string" && body.MessageId != "" {
            return #{ outcome: "accepted", providerReference: body.MessageId };
        }
        return #{ outcome: "maybe-sent" };
    }

    if response.status >= 500 {
        return #{ outcome: "maybe-sent" };
    }

    if is_map && type_of(body["__type"]) == "string" {
        // AWS JSON 1.0 may qualify the name with a namespace before `#` or a
        // suffix after `:`, as in `com.amazon.coral.service#ExpiredTokenException`.
        // The x-amzn-errortype header carries the same name, but the runtime
        // keeps x-amzn-* headers from scripts, so only the body is read.
        let exception = body["__type"].split(":")[0];
        let segments = exception.split("#");
        exception = segments[segments.len() - 1];
        if response.status == 400 && exception == "ThrottlingException" {
            return #{ outcome: "transient" };
        }
        let code = switch exception {
            "AccessDeniedException" => "aws.access-denied",
            "ConflictException" => "aws.conflict",
            "ExpiredTokenException" => "aws.expired-token",
            "IncompleteSignatureException" => "aws.incomplete-signature",
            "InvalidSignatureException" => "aws.invalid-signature",
            "MissingAuthenticationTokenException" => "aws.missing-authentication-token",
            "ResourceNotFoundException" => "aws.resource-not-found",
            "ServiceQuotaExceededException" => "aws.service-quota-exceeded",
            "UnrecognizedClientException" => "aws.unrecognized-client",
            "ValidationException" => "aws.validation",
            _ => (),
        };
        if type_of(code) == "string" {
            return #{ outcome: "permanent", code: code };
        }
    }

    #{ outcome: "maybe-sent" }
}

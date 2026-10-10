'use strict';
module.exports = {
  discovery: require('./discovery-client.darwin-arm64.node'),
  evidence: require('./evidence-client.darwin-arm64.node'),
  breg: require('./breg-client.darwin-arm64.node'),
  casework: require('./casework-client.darwin-arm64.node'),
  messaging: require('./messaging-client.darwin-arm64.node'),
  scheduling: require('./scheduling-client.darwin-arm64.node'),
  coordinator: require('./coordinator-client.darwin-arm64.node'),
};

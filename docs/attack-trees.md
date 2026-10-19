# Attack trees

An attack tree starts from a goal ("read another customer's invoice") and breaks
it into the steps that would be required. Each leaf is a condition an attacker
must satisfy.

## Example

Goal: read another customer's invoice.

- Guess an invoice identifier
  - Identifiers are sequential → high likelihood
  - Access control missing on the endpoint → high impact
- Obtain a valid session for another user
  - Session fixation
  - Stolen cookie without `HttpOnly`

## Why they help

- They make assumptions visible: "nobody will guess the ID" is now a leaf that
  can be challenged.
- They point at the cheapest mitigation: authorization on the object, not
  obscurity of the identifier.

local claims = {
  email_verified: true,
} + std.extVar('claims');

{
  identity: {
    traits: {
      claims.email
    },
  },
}
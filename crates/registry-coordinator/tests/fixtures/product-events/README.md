# BReg record event fixture

`breg-application-created-v1.schema.json` is the unchanged event data schema
exported by `bregctl generate schemas` for the native product-event runner's
synthetic application-created hook with a tenant-only projection. BReg owns
this schema vocabulary and numeric revision annotation.

Regenerate through `products/coordinator/scripts/test-breg-events.py`; its
source fixture and native checks use a fresh BReg export. The focused compiler
regression retains this generated sample so validation can run without services.

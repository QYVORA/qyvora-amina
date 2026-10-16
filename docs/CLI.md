# CLI Reference

`amina` follows the shared QYVORA tier grammar:

```
amina <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon`, `exploit`, or `report`. Every pre-tier command remains available as a hidden alias.

## recon

| Command | Purpose |
|---------|---------|
| `amina recon assess` | Run the host assessment |
| `amina recon scan` | Alias of assess |

## exploit

| Command | Purpose |
|---------|---------|
| `amina exploit exploit` | Report that exploitation has no modules |

## report

| Command | Purpose |
|---------|---------|
| `amina report assess` | Produce the assessment report |
| `amina report scan` | Produce the assessment report |

## Utilities

| Command | Purpose |
|---------|---------|
| `amina capabilities` | Machine-readable capability contract |
| `amina update` | Self-update |
| `amina version` | Print version |


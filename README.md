# sample-requirer

This charm is a Proof of Concept for validating the [goops](https://github.com/gruyaume/goops) library.

The charm supports a typical charm integration:
- `certificates` for TLS certificate management

## Getting Started

```shell
charmcraft pack --verbose
juju deploy ./sample-requirer.charm
```
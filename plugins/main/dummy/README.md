# dummy

CNI plugin to add IP address to the dummy interface of a container's network namespace.

This CNI plugin will create a `dummy0` interface if it does not already exist and add all of the configured IP addresses.

This CNI plugin can be either chained or unchained.

## Configuration

CNI configuration to add `169.254.169.254` to interface `dummy0`.

```json
{
    "cniVersion": "0.3.0",
    "name": "dummy-cni-config",
    "type": "dummy",
    "addresses": [
        "169.254.169.254/32"
    ]
}
```

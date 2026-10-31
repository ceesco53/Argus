# Known limitations

[← Back to Argus](../README.md)

- Monitor mode observes after the fact; it can't hold or block a connection.
- Server locations are where an address block is *registered*, which for large CDNs may differ from where
  the server physically is.
- Without Local Network permission macOS hides the router's hardware address, so networks are recognised
  by router address until you click **Identify Router** in Profiles. Wi-Fi names need Location Services.
- The sandboxed filter can't inspect other users' processes for `/dev/bpf` access; detection is limited
  to what the sandbox allows.

# Known limitations

[← Back to Argus](../README.md)

- Monitor mode observes after the fact; it can't hold or block a connection.
- Server locations are where an address block is *registered*, which for large CDNs may differ from where
  the server physically is.
- Without Local Network permission macOS hides the router's hardware address, so networks are recognised
  by router address until you click **Identify Router** in Profiles. Wi-Fi names need Location Services.
- The sandboxed filter can't inspect other users' processes for `/dev/bpf` access; detection is limited
  to what the sandbox allows.
- Ads are blocked by server, not by page. Argus can't see which page a connection is for, so allowing a
  server allows it on every site; it can't hide the empty space an ad leaves, or block ads a site
  serves from its own servers. Sites that use an anti-adblock service won't load with it blocked, and
  will show ads with it allowed.
- Check a page only sees new connections: a server the browser is already connected to may not show
  up when the page reloads. Blocked servers always do, since the browser keeps trying them. Argus can
  reload the page and read its address in Safari and Chromium browsers (Chrome, Edge, Brave, Vivaldi);
  in others, reload it yourself.

## Server
```bash
uv run l2server.py -i <interface>
```

## Client
```bash
uv run l2client.py -s <src-mac> -d <dst-mac> -i <interface> [-v <vlan-id>]
```

## Capture
```bash
tcpdump -vv -n -i any ether proto 2235 -XX
```


# librelaycore

`librelaycore` is the MFC-free C++17 core of the experimental KRP relay
protocol.

It provides:

- canonical unsigned LEB128 parsing;
- bounded KRP control frames;
- session and route-generation state;
- authenticated transcript binding;
- resumption-token consumption hooks;
- flow sequencing, half-close and memory budgets;
- optional endpoint-lease state;
- adapters for validated Kad6 target tickets.

The core does not open sockets, start threads, own UI state or store private
keys. Network transports and persistent policy belong to the host process.

## Runtime boundary

KRP is disabled by default in eSE 9.0.0-beta.1. A build containing this library
does not advertise or operate a public relay unless the independent runtime
preferences, authorization and kill switches allow it.

Raw arbitrary host/port forwarding is not part of the authority model.

## Build and test

From a Visual Studio developer prompt:

```bat
cd librelaycore
make.bat
```

For the sanitizer build:

```bat
set RELAY_ASAN=1
make.bat
```

The protocol values are registered in
[`docs/protocol/KRP_MESSAGES.csv`](../docs/protocol/KRP_MESSAGES.csv).

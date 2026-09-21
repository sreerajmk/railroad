# Railroad IPC demo

This directory demonstrates a simple inter-process communication pattern that combines:

- POSIX shared memory for fast state exchange
- POSIX message queues for structured notifications

## Build

```bash
cmake -S railroad/ipc -B railroad/ipc/build
cmake --build railroad/ipc/build
```

## Run

Start the producer and consumer in separate processes:

```bash
./railroad/ipc/build/railroad_ipc producer
./railroad/ipc/build/railroad_ipc consumer
```

The producer writes a shared-memory record and sends a queue message. The consumer reads the queue and updates the shared-memory state to confirm the exchange.

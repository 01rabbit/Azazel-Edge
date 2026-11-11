"""Fixed synthetic TCP peers for the opt-in namespace trial; no product imports."""
import json
import selectors
import socket
import sys
import threading
import time

PORT = 18080
ATK = "10.91.1.2"
LEGIT = "10.91.2.2"
SERVER = "10.91.3.2"
GOAL_BYTES = 256 * 1024
MAX_MESSAGE = 16384


def emit(value):
    raw = json.dumps(value, separators=(",", ":"))
    if len(raw) > MAX_MESSAGE:
        raise ValueError("peer audit oversized")
    print(raw, flush=True)


def service(nonce):
    started = time.monotonic_ns()
    sel = selectors.DefaultSelector()
    listener = socket.socket()
    listener.bind((SERVER, PORT))
    listener.listen(16)
    listener.setblocking(False)
    sel.register(listener, selectors.EVENT_READ, None)
    emit(dict(kind="ready", nonce=nonce))
    begin = json.loads(sys.stdin.buffer.readline(MAX_MESSAGE + 1))
    origin, deadline = begin["origin_ns"], begin["deadline_ns"]
    if begin["nonce"] != nonce or not started <= origin < deadline:
        raise ValueError("invalid measurement window")
    goal = None
    connections = 0
    legit = 0
    try:
        while time.monotonic_ns() < deadline:
            for key, _ in sel.select(min(.05, max(0, (deadline-time.monotonic_ns())/1e9))):
                if key.fileobj is listener:
                    connection, address = listener.accept()
                    connections += 1
                    if connections > 16 or address[0] not in (ATK, LEGIT):
                        connection.close()
                        raise ValueError("unexpected service client/budget")
                    connection.setblocking(False)
                    sel.register(connection, selectors.EVENT_READ, [address[0], bytearray(), 0])
                else:
                    connection = key.fileobj
                    source, prefix, count = key.data
                    data = connection.recv(16384)
                    if not data:
                        sel.unregister(connection)
                        connection.close()
                        continue
                    if not prefix:
                        prefix.extend(data[:1])
                        data = data[1:]
                    if prefix == b"L" and source == LEGIT:
                        if data:
                            raise ValueError("unexpected legitimate body")
                        connection.send(b"ok\n")
                        legit += 1
                        sel.unregister(connection)
                        connection.close()
                    elif prefix == b"G" and source == ATK:
                        key.data[2] += len(data)
                        if key.data[2] > GOAL_BYTES:
                            raise ValueError("objective payload exceeds bound")
                        if key.data[2] == GOAL_BYTES:
                            at = time.monotonic_ns()
                            if at < deadline:
                                if goal is not None:
                                    raise ValueError("duplicate objective")
                                goal = at  # service-owned state commit, independent of ACK
                                try:
                                    connection.send(b"committed\n")
                                except OSError:
                                    pass
                            sel.unregister(connection)
                            connection.close()
                    else:
                        raise ValueError("unexpected fixed service operation")
        # A completed audit proves the service remained alive to the real horizon.
        emit(dict(kind="audit", nonce=nonce, started_ns=started, ended_ns=time.monotonic_ns(),
                  origin_ns=origin, deadline_ns=deadline, goal_ns=goal,
                  legitimate_accepted=legit, connections=connections))
    finally:
        for key in list(sel.get_map().values()):
            key.fileobj.close()
        sel.close()


def client(nonce, origin, deadline):
    rows = []
    ack = False
    def wait_until(at):
        while time.monotonic_ns() < at:
            time.sleep(min(.01, (at-time.monotonic_ns())/1e9))
    def connect(source):
        connection = socket.socket()
        connection.settimeout(max(.001, (deadline-time.monotonic_ns())/1e9))
        connection.bind((source, 0))
        connection.connect((SERVER, PORT))
        return connection
    def objective():
        nonlocal ack
        wait_until(origin + 400_000_000)
        connection = None
        try:
            connection = connect(ATK)
            connection.settimeout(max(.001, (deadline-time.monotonic_ns())/1e9))
            connection.sendall(b"G" + b"x" * GOAL_BYTES)
            if time.monotonic_ns() < deadline:
                connection.settimeout(max(.001, (deadline-time.monotonic_ns())/1e9))
                ack = connection.recv(32) == b"committed\n"
        except OSError:
            pass
        finally:
            if connection is not None:
                connection.close()
    goal = threading.Thread(target=objective, daemon=True)
    goal.start()
    for number in range(6):
        wait_until(origin + 200_000_000 + number * 600_000_000)
        start = time.monotonic_ns()
        if start >= deadline:
            raise ValueError("legitimate request started outside window")
        connection = None
        error = True
        try:
            connection = connect(LEGIT)
            connection.settimeout(max(.001, (deadline-time.monotonic_ns())/1e9))
            connection.sendall(b"L")
            connection.settimeout(max(.001, (deadline-time.monotonic_ns())/1e9))
            error = connection.recv(32) != b"ok\n"
        except OSError:
            pass
        finally:
            if connection is not None:
                connection.close()
        end = time.monotonic_ns()
        if end > deadline:
            raise ValueError("legitimate result outside actual window")
        rows.append(dict(id="legitimate-" + str(number), elapsed_seconds=(end-origin)/1e9,
                         duration_ms=(end-start)/1e6, error=error))
    wait_until(deadline)
    goal.join(timeout=1)
    if goal.is_alive():
        raise ValueError("objective client failed to stop")
    emit(dict(kind="client", nonce=nonce, ended_ns=time.monotonic_ns(),
              transactions=rows, objective_ack=ack))


if __name__ == "__main__":
    if sys.argv[1] == "service" and len(sys.argv) == 3:
        service(sys.argv[2])
    elif sys.argv[1] == "client" and len(sys.argv) == 5:
        client(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    else:
        raise SystemExit("fixed namespace measurement peer only")

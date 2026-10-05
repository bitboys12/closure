import asyncio
import json
import urllib.request
import websockets

async def test_ws():
    req = urllib.request.Request(
        "http://localhost:8000/api/request",
        data=json.dumps({"command": "node packages/rogue-pkg/payload.js"}).encode(),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req) as resp:
        sess = json.loads(resp.read().decode())
    session_id = sess["session_id"]
    print("Session created:", session_id)

    async with websockets.connect(f"ws://localhost:8000/ws/{session_id}") as ws:
        await ws.send(json.dumps({"type": "APPROVE"}))
        while True:
            raw = await ws.recv()
            data = json.loads(raw)
            mtype = data.get("type")
            if mtype == "SYSCALL":
                sc = data["data"]["syscall"]
                tg = data["data"]["target"]
                print(f"[SYSCALL] {sc} -> {tg}")
            elif mtype == "VIOLATION":
                v_sc = data["data"]["syscall"]
                v_tg = data["data"]["target"]
                print(f"🚨 [VIOLATION EVENT] BLOCKED: {v_sc}('{v_tg}') -> Action: SIGKILL")
            elif mtype == "FINISHED":
                status = data["data"]["status"]
                print(f"🏁 [FINISHED] Final Status: {status}")
                break

if __name__ == "__main__":
    asyncio.run(test_ws())

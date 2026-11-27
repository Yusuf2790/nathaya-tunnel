#!/usr/bin/env python3
import asyncio


async def main():
    workers = []
    try:
        for port in (7100, 7200, 7300):
            workers.append(await asyncio.create_subprocess_exec(
                '/opt/nathaya/bin/badvpn-udpgw', '--listen-addr', f'127.0.0.1:{port}',
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        await asyncio.wait([asyncio.create_task(p.wait()) for p in workers],
                           return_when=asyncio.FIRST_COMPLETED)
        raise SystemExit(1)
    finally:
        for proc in workers:
            if proc.returncode is None:
                proc.terminate()
        await asyncio.gather(*(proc.wait() for proc in workers))


if __name__ == '__main__':
    asyncio.run(main())

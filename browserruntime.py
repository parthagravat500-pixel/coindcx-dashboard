"""Install a pinned official browser runtime in the existing private data disk.

Only the application entry point calls prepare(). Imports and tests never install
software. There are no apt changes, new services, public endpoints or credentials
in the child environment. Installation failure leaves HTML mapping available.
"""
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

PACKAGE='playwright==1.63.0'
STATUS={'state':'not_started','ready':False,'package':PACKAGE}


def status():return dict(STATUS)


def prepare(root):
    global STATUS
    cache=Path(root)/'browser-runtime';packages=cache/'packages';browsers=cache/'browsers'
    STATUS={'state':'preparing','ready':False,'package':PACKAGE}
    def finish(state,ready=False):
        global STATUS
        STATUS={'state':state,'ready':ready,'package':PACKAGE,'checked':int(time.time())}
        print(json.dumps({'kind':'scopeguard_browser_runtime',**STATUS}),flush=True)
        return STATUS
    try:
        cache.mkdir(mode=0o700,parents=True,exist_ok=True)
        env={key:os.environ[key] for key in ('PATH','HOME','LANG','LD_LIBRARY_PATH','SSL_CERT_FILE') if key in os.environ}
        env.update(PLAYWRIGHT_BROWSERS_PATH=str(browsers),PYTHONPATH=str(packages),
                   PIP_NO_CACHE_DIR='1',PIP_DISABLE_PIP_VERSION_CHECK='1',PYTHONUNBUFFERED='1')
        marker=cache/'installed-version'
        if not marker.exists() or marker.read_text()!=PACKAGE:
            if shutil.disk_usage(cache).free<650*1024*1024:return finish('insufficient_existing_disk_space')
            subprocess.run([sys.executable,'-m','pip','install','--isolated','--no-cache-dir','--only-binary=:all:',
                '--index-url','https://pypi.org/simple','--upgrade','--target',str(packages),PACKAGE],env=env,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=240)
            subprocess.run([sys.executable,'-m','playwright','install','chromium','--only-shell'],env=env,
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=240)
            marker.write_text(PACKAGE)
        # A real launch verifies shared libraries and browser availability.
        subprocess.run([sys.executable,'-c',
            "from playwright.sync_api import sync_playwright\nwith sync_playwright() as p:\n b=p.chromium.launch(headless=True); b.close()"],
            env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=45)
        if str(packages) not in sys.path:sys.path.insert(0,str(packages))
        os.environ['PLAYWRIGHT_BROWSERS_PATH']=str(browsers)
        importlib.invalidate_caches()
        return finish('ready',True)
    except subprocess.TimeoutExpired:return finish('installation_timeout')
    except subprocess.CalledProcessError:return finish('installation_or_system_dependency_failed')
    except OSError:return finish('runtime_storage_unavailable')

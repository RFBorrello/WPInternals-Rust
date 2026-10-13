"""Generate a synthetic mode-transition replay. Contains no real phone identifiers."""
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
device = dict(id="synthetic-original", vendor_id=0x0421, product_id=0x0661,
              manufacturer="Nokia", product="Synthetic Lumia 909", serial="SYNTHETIC-ONLY",
              model="Lumia 1020", variant="RM-875", firmware="3051.test", platform_id=None,
              family="spec_a", mode="normal", interfaces=[])


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode()


def exchange(request, response=b""):
    return dict(request=list(request), response=list(response), error=None)


exchanges = []
for number, (method, key, value) in enumerate([
    ("ReadManufacturerModelName", "ManufacturerModelName", "RM-875_eu"),
    ("ReadProductCode", "ProductCode", "TEST"),
    ("ReadSwVersion", "SwVersion", "3051.test"),
]):
    # Rust serde_json::Value maps use sorted keys for reproducible wire bytes.
    request = json.dumps(dict(jsonrpc="2.0", id=number, method=method,
                              params=dict(MessageVersion=0)), sort_keys=True, separators=(",", ":")).encode()
    exchanges.append(exchange(request, encoded(dict(jsonrpc="2.0", id=number, result={key: value}))))
command = json.dumps(dict(jsonrpc="2.0", id=3, method="SetDeviceMode",
                          params=dict(DeviceMode="Flash", ResetMethod="HwReset", MessageVersion=0)),
                     sort_keys=True, separators=(",", ":")).encode()
exchanges.append(exchange(command))

platform = b"Nokia.MSM8960.P5217"
nokv = b"NOKV" + bytes([0, 2, 1, 0, 1, 0, 1, 5]) + len(platform).to_bytes(2, "big") + platform
fver = bytearray(17)
fver[:6] = b"NOKXFR"
fver[16] = 10
fver += b"3051.test\0"
returned = {**device, "id": "synthetic-returned", "product_id": 0x066e,
            "mode": "flash", "model": None, "variant": None, "firmware": None,
            "family": "unknown"}
scenario = dict(baseline=device, target="flash", exchanges=exchanges, observations=[
    dict(elapsed_ms=1, observation=dict(kind="disconnected")),
    dict(elapsed_ms=2, observation=dict(kind="permission_required")),
    dict(elapsed_ms=3, observation=dict(kind="connected", devices=[returned], probe=[
        exchange(b"NOKV", nokv), exchange(b"NOKXFR\0FVER", fver),
    ])),
])
(root / "tests/fixtures/mode-normal-to-flash.json").write_text(json.dumps(scenario, indent=2) + "\n", encoding="utf-8")

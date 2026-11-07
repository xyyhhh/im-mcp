"""
WeChat image resolver and decryptor.
Supports:
1. Legacy XOR format (auto-calculates XOR key from JPEG magic header FF D8).
2. WeChat 4.x V2 format (AES-128-ECB PKCS7 + unencrypted raw + XOR tail) using AES key.
"""

import os
import hashlib
import re
import struct
import base64
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from .config import (
    USER_WECHAT_DIR,
    get_decrypted_dir,
    get_files_root,
    get_decrypted_files_root,
)

_V2_MAGIC_FULL = b"\x07\x08V2\x08\x07"
_V1_MAGIC_FULL = b"\x07\x08V1\x08\x07"
# V1 的 AES 密钥是全局固定常量（过渡期格式，不随账号变化），
# 与 V2 的账号级密钥不同 —— 因此 V1 无需 image_aes_key 也能离线解密。
_V1_FIXED_KEY = b"cfcd208495d565ef"
MAX_INLINE_IMAGE_BYTES = 20 * 1024 * 1024
MAX_INLINE_IMAGE_PIXELS = 40_000_000


def _find_image_candidates(md5: str, search_roots: list[Path]) -> list[Path]:
    """Highest-quality local variants first; never mistake a thumbnail for full size."""
    if not re.fullmatch(r"[0-9a-fA-F]{32}", md5):
        return []
    names = [f"{md5}{suffix}.dat" for suffix in ("_h", "_h_W", "", "_W", "_t", "_t_W")]
    ranks = {name: index for index, name in enumerate(names)}
    for root in search_roots:
        if not root.exists():
            continue
        attach_dir = root / "msg" / "attach"
        if attach_dir.exists():
            matches = [
                p
                for p in attach_dir.glob(f"**/{md5}*.dat")
                if p.is_file() and p.name in ranks
            ]
            if matches:
                return sorted(matches, key=lambda p: (ranks[p.name], str(p)))
    return []


def _find_image_dat_by_md5(md5: str, search_roots: list[Path]) -> Optional[Path]:
    matches = _find_image_candidates(md5, search_roots)
    return matches[0] if matches else None


def image_dimensions(data: bytes) -> tuple[Optional[int], Optional[int]]:
    """Read dimensions without decoding pixels or adding an imaging dependency."""
    if (
        data.startswith(b"\x89PNG\r\n\x1a\n")
        and data[12:16] == b"IHDR"
        and len(data) >= 24
    ):
        return struct.unpack(">II", data[16:24])
    if data.startswith((b"GIF87a", b"GIF89a")) and len(data) >= 10:
        return struct.unpack("<HH", data[6:10])
    if data.startswith(b"\xff\xd8"):
        offset = 2
        while offset + 4 <= len(data):
            if data[offset] != 0xFF:
                break
            while offset < len(data) and data[offset] == 0xFF:
                offset += 1
            if offset >= len(data):
                break
            marker = data[offset]
            offset += 1
            if marker in (0xD9, 0xDA):
                break
            if marker == 0x01 or 0xD0 <= marker <= 0xD8:
                continue
            size = int.from_bytes(data[offset : offset + 2], "big")
            if size < 2 or offset + size > len(data):
                break
            if (
                marker
                in (
                    0xC0,
                    0xC1,
                    0xC2,
                    0xC3,
                    0xC5,
                    0xC6,
                    0xC7,
                    0xC9,
                    0xCA,
                    0xCB,
                    0xCD,
                    0xCE,
                    0xCF,
                )
                and size >= 8
            ):
                height, width = struct.unpack(">HH", data[offset + 3 : offset + 7])
                return width, height
            offset += size
    return None, None


def _save_mirrored_image(
    source: Path, roots: list[Path], data: bytes, fmt: str
) -> Path:
    """Preserve account-relative directories and original stem, changing extension only."""
    if fmt not in {"jpg", "png", "gif", "webp", "wxgf"}:
        raise ValueError("Unsupported image format")
    relative = None
    for root in roots:
        try:
            candidate = source.resolve().relative_to(root.resolve())
        except ValueError:
            continue
        if candidate.parts[:2] == ("msg", "attach"):
            relative = candidate.with_suffix("." + fmt)
            break
    if relative is None:
        raise ValueError("Image is outside the configured account attachment directory")
    output_root = get_decrypted_files_root().resolve()
    destination = (output_root / relative).resolve()
    destination.relative_to(output_root)  # Reject symlink escapes as well.
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        if destination.read_bytes() == data:
            return destination
    except FileNotFoundError:
        pass
    # Atomic replacement: simultaneous readers never receive a partially written image.
    import tempfile

    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent, delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(data)
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return destination


# ---------------------------------------------------------------------------
# V2 格式的 XOR 段使用**全局单字节**密钥。
#
# ⚠️ 原先按「每个文件」用 tail[-1] ^ 0xD9 推导 —— 这隐含假定明文以 JPEG 的
#    FF D9 (EOI) 结尾。对 JPEG 成立，但对 PNG/GIF/WebP 等（结尾是 IEND 等）
#    推出来的密钥是错的，会让整个 XOR 段（图片的绝大部分）变成乱码。
#    正确做法：从若干 JPEG 缩略图尾部投票推导一次，全局复用。
# ---------------------------------------------------------------------------
_XOR_KEY_CACHE: Dict[tuple, int] = {}


def _detect_xor_key(img_dir: Path, aes_key: bytes) -> Optional[int]:
    """从同目录的 JPEG 缩略图（明文尾必为 FF D9）投票推导全局 XOR 密钥。"""
    cache_key = (str(img_dir), hashlib.sha256(aes_key).digest())
    if cache_key in _XOR_KEY_CACHE:
        return _XOR_KEY_CACHE[cache_key]

    from Crypto.Cipher import AES as _AES

    votes: Dict[int, int] = {}
    try:
        thumbs = sorted(img_dir.glob("*_t.dat"))[:48]
    except OSError:
        thumbs = []
    for p in thumbs:
        try:
            with open(p, "rb") as fp:
                data = fp.read()
        except OSError:
            continue
        if len(data) < 32 or data[:6] != _V2_MAGIC_FULL:
            continue
        _aes_size, xor_size = struct.unpack("<II", data[6:14])
        if xor_size <= 0:
            continue
        try:
            head = _AES.new(aes_key[:16], _AES.MODE_ECB).decrypt(data[15:31])
        except Exception:
            break
        if head[:3] != b"\xff\xd8\xff":
            continue
        k = data[-1] ^ 0xD9
        votes[k] = votes.get(k, 0) + 1

    result = max(votes, key=votes.get) if votes else None
    if result is not None:
        _XOR_KEY_CACHE[cache_key] = result
    return result


def _find_thumbnail_sibling(dat_path: Path) -> Optional[Path]:
    """同目录下的 <md5>_t.dat 缩略图（解出来是可直接渲染的 JPEG）。"""
    base = dat_path.name[:-4] if dat_path.name.endswith(".dat") else dat_path.name
    for suffix in ("_t_W", "_t", "_h"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    for name in (f"{base}_t.dat", f"{base}_t_W.dat"):
        cand = dat_path.parent / name
        if cand.exists():
            return cand
    return None


def decrypt_image_dat(
    dat_path: Path, aes_key: Optional[bytes] = None
) -> Tuple[Optional[bytes], str, Optional[str]]:
    """
    Decrypt a WeChat .dat image file.
    Returns: (decrypted_bytes, format_ext, error_message)
    """
    if not dat_path.exists():
        return None, "", f"Image dat file not found: {dat_path}"
    if dat_path.stat().st_size > 64 * 1024 * 1024:
        return None, "", "Image exceeds the 64 MiB decoding limit"

    with open(dat_path, "rb") as fp:
        data = fp.read()

    if len(data) < 16:
        return None, "", "File too small or corrupted"

    head6 = data[:6]

    # Case 1: V2 / V1 Format (AES-128-ECB + XOR)
    if head6 in (_V2_MAGIC_FULL, _V1_MAGIC_FULL):
        if not aes_key and head6 == _V1_MAGIC_FULL:
            # V1 用固定密钥即可解，不该因为缺 image_aes_key 而失败
            aes_key = _V1_FIXED_KEY
        if not aes_key:
            return (
                None,
                "",
                "WeChat 4.x V2 image encryption requires image_aes_key (not currently loaded)",
            )

        try:
            from Crypto.Cipher import AES
        except ImportError:
            return None, "", "pycryptodome not installed, required for AES decryption"

        if len(data) < 15:
            return None, "", "Invalid V2 dat header"

        aes_size, xor_size = struct.unpack("<II", data[6:14])
        # PKCS7 aligned size
        aligned_aes_size = (
            aes_size + (16 - aes_size % 16) if aes_size % 16 != 0 else aes_size + 16
        )
        if 15 + aligned_aes_size + xor_size > len(data):
            return None, "", "Corrupted image segment lengths"

        cipher_part = data[15 : 15 + aligned_aes_size]
        if len(cipher_part) < aligned_aes_size:
            return None, "", "Corrupted V2 dat file (truncated AES payload)"

        try:
            cipher = AES.new(aes_key[:16], AES.MODE_ECB)
            dec_aes = cipher.decrypt(cipher_part)
            # Remove PKCS7 padding
            pad_len = dec_aes[-1]
            if (
                not 1 <= pad_len <= 16
                or dec_aes[-pad_len:] != bytes([pad_len]) * pad_len
            ):
                return None, "", "Invalid image padding; key may be incorrect"
            dec_aes = dec_aes[:-pad_len]
        except Exception as e:
            return None, "", f"AES decryption failed: {e}"

        # Tail XOR
        raw_mid = data[15 + aligned_aes_size : len(data) - xor_size]
        tail_xor = data[len(data) - xor_size :]

        if tail_xor:
            # XOR 密钥是**全局单字节**：优先从同目录 JPEG 缩略图投票推导
            # （对 PNG/GIF/WebP 也正确）；推不出来才退回老行为
            # （按本文件尾部 FF D9 推导，只对 JPEG 正确）。
            xor_key = None
            if aes_key:
                xor_key = _detect_xor_key(dat_path.parent, aes_key)
            if xor_key is None:
                xor_key = tail_xor[-1] ^ 0xD9
            dec_tail = bytes([b ^ xor_key for b in tail_xor])
        else:
            dec_tail = b""

        full_img = dec_aes + raw_mid + dec_tail
        if full_img.startswith(b"\xff\xd8\xff"):
            fmt = "jpg"
        elif full_img.startswith(b"\x89PNG"):
            fmt = "png"
        elif full_img.startswith(b"GIF8"):
            fmt = "gif"
        elif full_img.startswith(b"RIFF") and full_img[8:12] == b"WEBP":
            fmt = "webp"
        elif full_img.startswith(b"wxgf"):
            fmt = "wxgf"
        else:
            fmt = "bin"
        return full_img, fmt, None

    # Case 2: Legacy XOR format (Auto-detect XOR key)
    # JPEG magic: FF D8 FF
    k1 = data[0] ^ 0xFF
    k2 = data[1] ^ 0xD8
    if k1 == k2:
        xor_key = k1
        full_img = bytes([b ^ xor_key for b in data])
        return full_img, "jpg", None

    # PNG magic: 89 50 4E 47
    k1 = data[0] ^ 0x89
    k2 = data[1] ^ 0x50
    if k1 == k2:
        xor_key = k1
        full_img = bytes([b ^ xor_key for b in data])
        return full_img, "png", None

    # GIF magic: 47 49 46 38 ('GIF8')
    k1 = data[0] ^ 0x47
    k2 = data[1] ^ 0x49
    if k1 == k2:
        xor_key = k1
        full_img = bytes([b ^ xor_key for b in data])
        return full_img, "gif", None

    return None, "", "Unknown image dat encryption format"


# ---------------------------------------------------------------------------
# 图片 AES 密钥的读取与自动提取
#
# 微信 4.x V2 图片的密钥是账号级的，只在该账号查看图片时临时缓存于微信进程
# 内存、磁盘上没有任何副本 —— 因此「缺密钥」是可自愈的：解密失败时自动扫一次
# 内存（限时），命中即落盘，之后所有图片解密都直接可用，无需人工介入。
#
# 每个 MCP 进程只自动尝试一次：未命中说明此刻密钥不在内存（用户没刚看过图），
# 继续对每张图各扫十几秒只会把面板拖死，不如快速失败并如实提示。
# ---------------------------------------------------------------------------

_AUTO_IMAGE_KEY_ATTEMPTED = False


def _load_image_key(keys_path: Path) -> Optional[bytes]:
    """从密钥文件读取 image_aes_key（缺失 / 损坏时返回 None）。"""
    try:
        import json

        if not keys_path.exists():
            return None
        with open(keys_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        value = data.get("image_aes_key") if isinstance(data, dict) else None
        return value.encode("ascii") if value else None
    except Exception:  # noqa: BLE001 - 密钥文件异常按「没有密钥」处理
        return None


def _try_extract_image_key(max_seconds: float = 20.0) -> bool:
    """自动尝试一次从微信进程内存提取图片密钥；本进程只试一次。"""
    global _AUTO_IMAGE_KEY_ATTEMPTED
    if _AUTO_IMAGE_KEY_ATTEMPTED:
        return False
    _AUTO_IMAGE_KEY_ATTEMPTED = True
    try:
        from .tools.key_tool import extract_image_key

        root = get_files_root()
        db_dir = os.environ.get("WECHAT_DB_DIR") or (
            str(root / "db_storage") if root else None
        )
        return bool(
            extract_image_key(
                db_dir=db_dir,
                keys_file=str(USER_WECHAT_DIR / "all_keys.json"),
                max_seconds=max_seconds,
            ).get("ok")
        )
    except Exception:  # noqa: BLE001 - 自动提取失败不影响正常错误上报
        return False


def get_image_for_message(
    message_id: int,
    include_base64: bool = False,
    quality: str = "full",
    allow_large: bool = False,
) -> Dict[str, Any]:
    """
    Resolve and decrypt an image for a specific message ID.
    Returns dictionary with image path, metadata, and optional base64 content.
    """
    import sqlite3
    from .sources import source_exists, connect_source
    from .database import get_connection

    if quality not in {"full", "thumbnail"}:
        return {
            "error": "quality must be full or thumbnail",
            "error_code": "invalid_quality",
        }

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    row = cur.execute("SELECT * FROM messages WHERE id = ?", (message_id,)).fetchone()
    conn.close()
    if not row:
        return {"error": "Message not found", "error_code": "message_not_found"}

    if (row["local_type"] & 0xFFFFFFFF) != 3:
        return {
            "error": "The requested message is not an image",
            "error_code": "not_image",
        }

    source_file = row["source_file"]
    local_id = row["local_id"]
    create_time = row["create_time"]
    decrypted_dir = get_decrypted_dir()

    # 1. Try to find image MD5
    target_md5 = None

    # Prefer the exact source row. local_id can collide across chat tables.
    from contextlib import closing

    if source_file and Path(source_file).name == source_file:
        src_db = decrypted_dir / "message" / source_file
        if source_exists(src_db):
            try:
                with closing(connect_source(src_db)) as s_conn:
                    tbl = (
                        "Msg_"
                        + hashlib.md5(row["session_username"].encode()).hexdigest()
                    )
                    m_row = s_conn.execute(
                        f'SELECT packed_info_data FROM "{tbl}" WHERE local_id = ? AND create_time = ?',
                        (local_id, create_time),
                    ).fetchone()
                    if m_row and m_row[0]:
                        match = re.search(rb"[0-9a-fA-F]{32}", m_row[0])
                        if match:
                            target_md5 = match.group(0).decode("ascii").lower()
            except sqlite3.Error:
                pass

    res_db = decrypted_dir / "message" / "message_resource.db"
    if not target_md5 and source_exists(res_db):
        try:
            with closing(connect_source(res_db)) as r_conn:
                matches = r_conn.execute(
                    "SELECT packed_info FROM MessageResourceInfo WHERE message_create_time = ? AND message_local_id = ?",
                    (create_time, local_id),
                ).fetchall()
                md5s = set()
                for resource in matches:
                    match = re.search(rb"[0-9a-fA-F]{32}", resource[0] or b"")
                    if match:
                        md5s.add(match.group(0).decode("ascii").lower())
                if len(md5s) == 1:
                    target_md5 = md5s.pop()
        except sqlite3.Error:
            pass

    if not target_md5:
        return {
            "error": "Could not locate image metadata",
            "error_code": "metadata_not_found",
        }

    # 2. Search physical dat file
    # Look into possible WeChat root paths
    configured_root = get_files_root()
    candidates = (
        [configured_root]
        if configured_root
        else [
            Path.home() / "Documents" / "WeChat Files",
            Path(os.environ.get("APPDATA", "")) / "Tencent" / "WeChat",
        ]
    )
    # Check if we can auto-detect from config ini
    try:
        from .tools.key_tool import auto_detect_db_dir

        db_dir = None if configured_root else auto_detect_db_dir()
        if db_dir:
            # db_dir is like .../xwechat_files/<user_hash>/db_storage
            # parent is xwechat_files/<user_hash>
            user_root = Path(db_dir).parent
            candidates.insert(0, user_root)
    except Exception:
        pass

    all_keys_path = USER_WECHAT_DIR / "all_keys.json"
    if all_keys_path.exists():
        try:
            import json

            with open(all_keys_path, "r", encoding="utf-8") as f:
                k_data = json.load(f)
                if not configured_root and k_data.get("wechat_dir"):
                    candidates.insert(0, Path(k_data["wechat_dir"]))
        except Exception:
            pass

    variants = _find_image_candidates(target_md5, candidates)
    if not variants:
        return {
            "error": "Image is not present in local WeChat storage; open it in WeChat to download it.",
            "error_code": "image_not_downloaded",
            "md5": target_md5,
        }

    is_thumb = lambda path: path.name.endswith(("_t.dat", "_t_W.dat"))
    available_thumbnail = any(is_thumb(path) for path in variants)
    selected = [path for path in variants if is_thumb(path) == (quality == "thumbnail")]
    if not selected:
        return {
            "error": "Requested image quality has not been downloaded locally. Open the full image in WeChat first.",
            "error_code": (
                "original_not_downloaded"
                if quality == "full"
                else "thumbnail_not_downloaded"
            ),
            "available_thumbnail": available_thumbnail,
        }

    # Try every requested-quality variant before reporting a decoder failure.
    # A wxgf normal variant must never hide an available high-resolution JPEG.
    image_aes_key = _load_image_key(all_keys_path)
    failures = []
    for dat_file in selected:
        img_bytes, fmt, err = decrypt_image_dat(dat_file, aes_key=image_aes_key)
        if err and "image_aes_key" in err and _try_extract_image_key():
            image_aes_key = _load_image_key(all_keys_path)
            img_bytes, fmt, err = decrypt_image_dat(dat_file, aes_key=image_aes_key)
        if err:
            failures.append(
                "image_key_missing"
                if "image_aes_key" in err
                else "image_decryption_failed"
            )
            continue
        if fmt == "wxgf":
            _save_mirrored_image(dat_file, candidates, img_bytes, fmt)
        if fmt not in {"jpg", "png", "gif", "webp"}:
            failures.append("unsupported_image_format")
            continue
        break
    else:
        code = (
            "unsupported_image_format"
            if "unsupported_image_format" in failures
            else failures[0]
        )
        return {
            "error": "No requested-quality variant can be decoded. A thumbnail was not substituted.",
            "error_code": code,
            "available_thumbnail": available_thumbnail,
            "hint": "Open/download the original in WeChat. Thumbnail retrieval requires quality=thumbnail explicitly.",
        }

    # 4. Save decrypted image to cache
    out_file = _save_mirrored_image(dat_file, candidates, img_bytes, fmt)

    res = {
        "success": True,
        "message_id": message_id,
        "md5": target_md5,
        "format": fmt,
        "size_bytes": len(img_bytes),
        "file_path": str(out_file),
        "mime_type": "image/jpeg" if fmt == "jpg" else "image/" + fmt,
        "is_thumbnail": is_thumb(dat_file),
        "quality": quality,
        "source_variant": (
            "thumbnail"
            if is_thumb(dat_file)
            else "high" if dat_file.name.endswith(("_h.dat", "_h_W.dat")) else "normal"
        ),
    }
    width, height = image_dimensions(img_bytes)
    res.update(width=width, height=height)
    if failures:
        res["warning"] = (
            "A higher-priority full-size variant could not be decoded; this is the best readable local full-size variant."
        )
    if res["is_thumbnail"]:
        res["warning"] = (
            "Only a thumbnail is available for viewing; small text may be unreadable. Do not infer uncertain names or dates."
        )

    if include_base64:
        if not allow_large and (
            len(img_bytes) > MAX_INLINE_IMAGE_BYTES
            or (width and height and width * height > MAX_INLINE_IMAGE_PIXELS)
        ):
            res.update(
                success=False,
                error="Image exceeds the normal full-image transfer limit; no thumbnail was substituted.",
                error_code="image_too_large",
                limit_bytes=MAX_INLINE_IMAGE_BYTES,
                limit_pixels=MAX_INLINE_IMAGE_PIXELS,
                hint="Inspect metadata or explicitly set allow_large=true (decoder hard limit: 64 MiB).",
            )
            return res
        res["base64"] = base64.b64encode(img_bytes).decode("ascii")

    return res

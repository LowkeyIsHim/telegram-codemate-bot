"""
handlers/exif.py — extracts metadata (camera model, timestamp, GPS
coordinates) from a photo. This is a real, widely-used OSINT technique —
people frequently leak their location or device info in photo metadata
without realizing it. It's also why photographers and journalists are
taught to strip EXIF before publishing sensitive images.

IMPORTANT: Telegram recompresses images sent as a "Photo", which strips
EXIF data entirely. To preserve metadata, the image must be sent as a
"File"/"Document" instead (uncompressed, original bytes). Just send the
file directly — no need to reply or run a command first, this fires
automatically on any image file upload.
"""

import io
from core import bot
from formatting import safe_reply

INTERESTING_TAGS = ["Make", "Model", "DateTime", "Software", "ImageWidth", "ImageLength"]


def _convert_gps(coord, ref):
    """Convert an EXIF (degrees, minutes, seconds) GPS tuple to decimal."""
    if not coord or not ref:
        return None
    try:
        degrees, minutes, seconds = coord
        decimal = float(degrees) + float(minutes) / 60 + float(seconds) / 3600
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 6)
    except Exception:
        return None


def get_exif_text(image_bytes: bytes) -> str:
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS, GPSTAGS

        img = Image.open(io.BytesIO(image_bytes))
        exif_data = img.getexif()
        if not exif_data:
            return (
                "📷 No EXIF metadata found — it may have been stripped already "
                "(or the image was sent as a compressed Photo, which always "
                "strips it — send as a File/Document instead)."
            )

        tags = {}
        for tag_id, value in exif_data.items():
            tags[TAGS.get(tag_id, tag_id)] = value

        lines = []
        for key in INTERESTING_TAGS:
            if key in tags:
                lines.append(f"{key}: {tags[key]}")

        # GPS lives in a nested IFD (0x8825), not the flat top-level tags —
        # the top-level "GPSInfo" entry is just a pointer, not the data itself.
        gps_ifd = exif_data.get_ifd(0x8825) if hasattr(exif_data, "get_ifd") else None
        if gps_ifd:
            gps_info = {GPSTAGS.get(k, k): v for k, v in gps_ifd.items()}
            lat = _convert_gps(gps_info.get("GPSLatitude"), gps_info.get("GPSLatitudeRef"))
            lon = _convert_gps(gps_info.get("GPSLongitude"), gps_info.get("GPSLongitudeRef"))
            if lat is not None and lon is not None:
                lines.append(f"\n📍 GPS: {lat}, {lon}")
                lines.append(f"Maps: https://maps.google.com/?q={lat},{lon}")

        if not lines:
            return "EXIF data present but no notable fields (camera/GPS) found."
        return "📷 *Photo Metadata Found:*\n" + "\n".join(lines)
    except Exception as e:
        return f"⚠️ Could not read image/EXIF data: {e}"


@bot.message_handler(commands=["exif"])
def exif_cmd(message):
    bot.reply_to(
        message,
        "Send the photo as a *File/Document* (not as a compressed Photo — "
        "Telegram strips all metadata from regular photo uploads) and I'll "
        "extract any EXIF data automatically.",
        parse_mode="Markdown",
    )


@bot.message_handler(content_types=["document"])
def document_handler(message):
    doc = message.document
    if not doc.mime_type or not doc.mime_type.startswith("image/"):
        return  # not an image file — ignore silently, could be any other document
    bot.send_chat_action(message.chat.id, "typing")
    try:
        file_info = bot.get_file(doc.file_id)
        downloaded = bot.download_file(file_info.file_path)
    except Exception as e:
        bot.reply_to(message, f"⚠️ Couldn't download the file: {e}")
        return
    safe_reply(message, get_exif_text(downloaded))

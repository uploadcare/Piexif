import collections
from struct import unpack_from

from ._common import *
from ._exceptions import InvalidImageDataError
from ._exif import *
from piexif import _webp

LITTLE_ENDIAN = b"\x49\x49"


Tag = collections.namedtuple('Tag', 'tag type value offset')


def load(input_data, key_is_name=False):
    """
    py:function:: piexif.load(filename)

    Return exif data as dict. Keys(IFD name), be contained, are "0th", "Exif", "GPS", "Interop", "1st", and "thumbnail". Without "thumbnail", the value is dict(tag name/tag value). "thumbnail" value is JPEG as bytes.

    :param str filename: JPEG or TIFF
    :return: Exif data({"0th":dict, "Exif":dict, "GPS":dict, "Interop":dict, "1st":dict, "thumbnail":bytes})
    :rtype: dict
    """
    loader = ExifLoader(key_is_name=key_is_name)
    tiff_data = extract_tiff_data(input_data)
    if tiff_data:
        loader.load(tiff_data)
    return loader.exif


def extract_tiff_data(data, treat_as_path=True):
    if data[0:2] == b"\xff\xd8":  # JPEG
        segments = split_into_segments(data)
        app1 = get_exif_seg(segments)
        if app1:
            tiff_data = app1[10:]
        else:
            tiff_data = None
    elif data[0:2] in (b"\x49\x49", b"\x4d\x4d"):  # TIFF
        tiff_data = data
    elif data[0:4] == b"RIFF" and data[8:12] == b"WEBP":
        tiff_data = _webp.get_exif(data)
    elif data[0:4] == b"Exif":  # Exif
        tiff_data = data[6:]
    else:
        if treat_as_path:
            with open(data, 'rb') as f:
                return extract_tiff_data(f.read(), False)
        else:
            raise InvalidImageDataError("Given image is neither JPEG, WEBP nor TIFF.")
    if not tiff_data:
        return None
    return tiff_data



class ExifLoader(object):
    def __init__(self, read_unknown=False, key_is_name=False):
        self._read_unknown = read_unknown
        self._key_is_name = key_is_name
        self._reader = None
        self._tiff_data = None
        self.exif = self._blank_exif()

    def _blank_exif(self):
        return {
            "0th": {},
            "Exif": {},
            "GPS": {},
            "Interop": {},
            "1st": {},
            "thumbnail": None
        }

    def _get_ifd(self, pointer, ifd_name):
        if not pointer or isinstance(pointer, tuple):
            # Skip null pointers, and catch cases, where pointer has zero or
            # multiple values
            return {}, None
        result = {}
        if ifd_name in ["0th", "1st"]:
            ifd_name = "Image"
        ifd, next = self._reader.get_ifd(pointer)
        for tag in ifd:
            known_tag = tag.tag in TAGS[ifd_name]
            if not (self._read_unknown or known_tag):
                continue
            values = tag.value
            if known_tag:
                expected_value_type = TAGS[ifd_name][tag.tag]['type']
                if tag.type != expected_value_type:
                    try:
                        values = coerce(values, tag.type, expected_value_type)
                    except ValueError:
                        # Skip if coercion failed
                        continue
            if len(values) == 1:
                values = values[0]
            result[tag.tag] = values
        return result, next

    def _load_ifd(self, name, pointer):
        ifd, next = self._get_ifd(pointer, name)
        self.exif[name] = ifd
        return next

    def _get(self, ifd_name, tag_name):
        return self.exif[ifd_name].get(tag_name, None)

    def _apply_tag_names(self):
        result = {}
        for name, tag_category in [
            ("0th", "Image"),
            ("1st", "Image"),
            ("Exif", "Exif"),
            ("GPS", "GPS"),
        ]:
            result[name] = {}
            for tag, value in self.exif[name].items():
                if tag not in TAGS[tag_category]:
                    continue
                tag_name = TAGS[tag_category][tag]["name"]
                result[name][tag_name] = value
        result["thumbnail"] = self.exif["thumbnail"]
        self.exif = result

    def load(self, tiff_data):
        self.exif = self._blank_exif()
        self._reader = TiffReader(tiff_data)
        self._tiff_data = tiff_data

        first_ifd_pointer = self._load_ifd("0th", self._reader.root_pointer)
        self._load_ifd("1st", first_ifd_pointer)
        CHILD_IFDS = [
            ("Exif", "0th", ImageIFD.ExifTag),
            ("GPS", "0th", ImageIFD.GPSTag),
            ("Interop", "Exif", ExifIFD.InteroperabilityTag),
        ]
        for name, parent, tag in CHILD_IFDS:
            pointer = self._get(parent, tag)
            self._load_ifd(name, pointer)

        thumb_off = self._get("1st", ImageIFD.JPEGInterchangeFormat)
        thumb_len = self._get("1st", ImageIFD.JPEGInterchangeFormatLength)
        if thumb_off and thumb_len:
            thumb = self._tiff_data[thumb_off:thumb_off + thumb_len]
            self.exif["thumbnail"] = thumb

        if self._key_is_name:
            self._apply_tag_names()

class TiffReader(object):
    def __init__(self, data):
        self.tiftag = data
        if len(data) < 8:
            # `get_ifd` will consider it cropped IFD and return `[]`,
            # which is reasonable behaviour
            self.endian_mark = ">"
            self.root_pointer = 0
            return
        if self.tiftag[0:2] == LITTLE_ENDIAN:
            self.endian_mark = "<"
        else:
            self.endian_mark = ">"
        self.root_pointer, = self._unpack_from("L",  4)

    def _unpack_from(self, format, pointer):
        return unpack_from(self.endian_mark + format, self.tiftag, pointer)

    def _read_tag(self, pointer):
        tag, value_type, value_num = self._unpack_from("HHL", pointer)
        if value_type not in TYPE_FORMAT:
            return None
        value_length = TYPE_LENGTH.get(value_type, 1) * value_num
        if value_length > 4:
            data_pointer, = self._unpack_from("L", pointer + 8)
        else:
            data_pointer = pointer + 8
        if data_pointer + value_length > len(self.tiftag):
            return None

        format = TYPE_FORMAT.get(value_type, None)

        if format is None:
            raw_value = self.tiftag[data_pointer:data_pointer+value_length]
            # Ascii, Undefined and unknown types
            if value_type == TYPES.Ascii:
                # Crop ending zero
                raw_value = raw_value.split(b'\0')[0]
            values = (raw_value, )
        else:
            # Unpacked types
            values = self._unpack_from(format * value_num, data_pointer)
            # Collate rationals
            if len(format) > 1:
                values = zip(*[iter(values)] * len(format))
        return Tag(tag, value_type, tuple(values), pointer)

    def get_ifd(self, pointer):
        if pointer > len(self.tiftag) - 2:
            return [], None
        result = []
        tag_count, = self._unpack_from("H", pointer)
        offset = pointer + 2
        tag_count = min(tag_count, (len(self.tiftag) - offset) // 12)
        for x in range(tag_count):
            pointer = offset + 12 * x
            tag = self._read_tag(pointer)
            if not tag:
                # Skip broken tags
                continue
            result.append(tag)

        pointer = offset + 12 * tag_count
        if pointer + 4 < len(self.tiftag):
            next, = self._unpack_from("L", pointer)
            if not next:
                next = None
        else:
            next = None

        return result, next



def coerce(value, type, target):
    if target == TYPES.Undefined:
        if type == TYPES.Byte:
            # Interpret numbers as byte values, to fit Pillow behaviour
            return ( bytes(value), )
    elif target in SIMPLE_NUMERICS:
        if type in SIMPLE_NUMERICS:
            return value
    raise ValueError('cannot coerce %s to %s' % (type, target))

import sys
from struct import unpack_from

from ._common import *
from ._exceptions import InvalidImageDataError
from ._exif import *
from piexif import _webp

LITTLE_ENDIAN = b"\x49\x49"


def load(input_data, key_is_name=False):
    """
    py:function:: piexif.load(filename)

    Return exif data as dict. Keys(IFD name), be contained, are "0th", "Exif", "GPS", "Interop", "1st", and "thumbnail". Without "thumbnail", the value is dict(tag name/tag value). "thumbnail" value is JPEG as bytes.

    :param str filename: JPEG or TIFF
    :return: Exif data({"0th":dict, "Exif":dict, "GPS":dict, "Interop":dict, "1st":dict, "thumbnail":bytes})
    :rtype: dict
    """
    exif_dict = {"0th":{},
                 "Exif":{},
                 "GPS":{},
                 "Interop":{},
                 "1st":{},
                 "thumbnail":None}
    exifReader = _ExifReader.from_image(input_data)
    if exifReader is None:
        return exif_dict

    exif_dict["0th"], first_ifd_pointer = exifReader.get_ifd_dict(exifReader.root_pointer, "0th")
    CHILD_IFDS = [
        ("Exif", "0th", ImageIFD.ExifTag),
        ("GPS", "0th", ImageIFD.GPSTag),
        ("Interop", "Exif", ExifIFD.InteroperabilityTag),
    ]
    for name, parent, tag in CHILD_IFDS:
        if tag in exif_dict[parent]:
            pointer = exif_dict[parent][tag]
            if isinstance(pointer, tuple):
                # To catch cases, where there are zero or multiple values
                continue
            exif_dict[name] = exifReader.get_ifd_dict(pointer, name)[0]
    if first_ifd_pointer:
        exif_dict["1st"] = exifReader.get_ifd_dict(first_ifd_pointer, "1st")[0]
        start = exif_dict["1st"].get(ImageIFD.JPEGInterchangeFormat, None)
        length = exif_dict["1st"].get(ImageIFD.JPEGInterchangeFormatLength, None)
        if isinstance(start, int) and isinstance(length, int):
            end = start + length
            thumb = exifReader.tiftag[start:end]
            exif_dict["thumbnail"] = thumb

    if key_is_name:
        exif_dict = _get_key_name_dict(exif_dict)
    return exif_dict


class _ExifReader(object):
    @classmethod
    def from_image(cls, data, treat_as_path=True):
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
                    return cls.from_image(f.read(), False)
            else:
                raise InvalidImageDataError("Given image is neither JPEG, WEBP nor TIFF.")
        if not tiff_data:
            return None
        return cls(tiff_data)

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
        return tag, value_type, tuple(values)

    def get_ifd_dict(self, pointer, ifd_name, read_unknown=False):
        ifd_dict = {}
        if pointer > len(self.tiftag) - 2:
            return {}, None
        tag_count, = self._unpack_from("H", pointer)
        offset = pointer + 2
        tag_count = min(tag_count, (len(self.tiftag) - offset) // 12)
        if ifd_name in ["0th", "1st"]:
            t = "Image"
        else:
            t = ifd_name
        for x in range(tag_count):
            pointer = offset + 12 * x
            read_result = self._read_tag(pointer)
            if not read_result:
                # Skip broken tags
                continue
            tag, value_type, values = read_result
            if tag in TAGS[t]:
                expected_value_type = TAGS[t][tag]['type']
                if value_type != expected_value_type:
                    try:
                        values = coerce(values, value_type, expected_value_type)
                    except ValueError:
                        # Skip if coercion failed
                        continue
                if len(values) == 1:
                    values = values[0]
                ifd_dict[tag] = values
            elif read_unknown:
                value_num, = self._unpack_from("L", pointer + 4)
                pointer_or_value = self.tiftag[pointer + 8: pointer + 12]
                ifd_dict[tag] = value_type, value_num, pointer_or_value, self.tiftag
            else:
                pass

        pointer = offset + 12 * tag_count
        if pointer + 4 < len(self.tiftag):
            next, = self._unpack_from("L", pointer)
            if not next:
                next = None
        else:
            next = None

        return ifd_dict, next


def _get_key_name_dict(exif_dict):
    new_dict = {
        "0th":{TAGS["Image"][n]["name"]:value for n, value in exif_dict["0th"].items()},
        "Exif":{TAGS["Exif"][n]["name"]:value for n, value in exif_dict["Exif"].items()},
        "1st":{TAGS["Image"][n]["name"]:value for n, value in exif_dict["1st"].items()},
        "GPS":{TAGS["GPS"][n]["name"]:value for n, value in exif_dict["GPS"].items()},
        "Interop":{TAGS["Interop"][n]["name"]:value for n, value in exif_dict["Interop"].items()},
        "thumbnail":exif_dict["thumbnail"],
    }
    return new_dict

def coerce(value, type, target):
    if target == TYPES.Undefined:
        if type == TYPES.Byte:
            # Interpret numbers as byte values, to fit Pillow behaviour
            return ( bytes(value), )
    elif target in SIMPLE_NUMERICS:
        if type in SIMPLE_NUMERICS:
            return value
    raise ValueError('cannot coerce %s to %s' % (type, target))

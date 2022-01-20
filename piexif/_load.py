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
    exifReader = _ExifReader(input_data)
    if exifReader.tiftag is None:
        return exif_dict

    if exifReader.tiftag[0:2] == LITTLE_ENDIAN:
        exifReader.endian_mark = "<"
    else:
        exifReader.endian_mark = ">"

    pointer = unpack_from(exifReader.endian_mark + "L",
                          exifReader.tiftag, 4)[0]
    exif_dict["0th"] = exifReader.get_ifd_dict(pointer, "0th")
    first_ifd_pointer = exif_dict["0th"].pop("first_ifd_pointer")
    if ImageIFD.ExifTag in exif_dict["0th"]:
        pointer = exif_dict["0th"][ImageIFD.ExifTag]
        exif_dict["Exif"] = exifReader.get_ifd_dict(pointer, "Exif")
    if ImageIFD.GPSTag in exif_dict["0th"]:
        pointer = exif_dict["0th"][ImageIFD.GPSTag]
        exif_dict["GPS"] = exifReader.get_ifd_dict(pointer, "GPS")
    if ExifIFD.InteroperabilityTag in exif_dict["Exif"]:
        pointer = exif_dict["Exif"][ExifIFD.InteroperabilityTag]
        exif_dict["Interop"] = exifReader.get_ifd_dict(pointer, "Interop")
    if first_ifd_pointer != b"\x00\x00\x00\x00":
        pointer = unpack_from(exifReader.endian_mark + "L",
                              first_ifd_pointer)[0]
        exif_dict["1st"] = exifReader.get_ifd_dict(pointer, "1st")
        if (ImageIFD.JPEGInterchangeFormat in exif_dict["1st"] and
            ImageIFD.JPEGInterchangeFormatLength in exif_dict["1st"]):
            end = (exif_dict["1st"][ImageIFD.JPEGInterchangeFormat] +
                   exif_dict["1st"][ImageIFD.JPEGInterchangeFormatLength])
            thumb = exifReader.tiftag[exif_dict["1st"][ImageIFD.JPEGInterchangeFormat]:end]
            exif_dict["thumbnail"] = thumb

    if key_is_name:
        exif_dict = _get_key_name_dict(exif_dict)
    return exif_dict


class _ExifReader(object):
    def __init__(self, data):
        # Prevents "UnicodeWarning: Unicode equal comparison failed" warnings on Python 2
        maybe_image = sys.version_info >= (3,0,0) or isinstance(data, str)

        if maybe_image and data[0:2] == b"\xff\xd8":  # JPEG
            segments = split_into_segments(data)
            app1 = get_exif_seg(segments)
            if app1:
                self.tiftag = app1[10:]
            else:
                self.tiftag = None
        elif maybe_image and data[0:2] in (b"\x49\x49", b"\x4d\x4d"):  # TIFF
            self.tiftag = data
        elif maybe_image and data[0:4] == b"RIFF" and data[8:12] == b"WEBP":
            self.tiftag = _webp.get_exif(data)
        elif maybe_image and data[0:4] == b"Exif":  # Exif
            self.tiftag = data[6:]
        else:
            with open(data, 'rb') as f:
                magic_number = f.read(2)
            if magic_number == b"\xff\xd8":  # JPEG
                app1 = read_exif_from_file(data)
                if app1:
                    self.tiftag = app1[10:]
                else:
                    self.tiftag = None
            elif magic_number in (b"\x49\x49", b"\x4d\x4d"):  # TIFF
                with open(data, 'rb') as f:
                    self.tiftag = f.read()
            else:
                with open(data, 'rb') as f:
                    header = f.read(12)
                if header[0:4] == b"RIFF"and header[8:12] == b"WEBP":
                    with open(data, 'rb') as f:
                        file_data = f.read()
                    self.tiftag = _webp.get_exif(file_data)
                else:
                    raise InvalidImageDataError("Given file is neither JPEG nor TIFF.")

    def _unpack_from(self, format, pointer):
        return unpack_from(self.endian_mark + format, self.tiftag, pointer)

    def _read_tag(self, pointer):
        tag, value_type, value_num = self._unpack_from("HHL", pointer)
        # Treat unknown types as `Undefined`
        value_length = TYPE_LENGTH.get(value_type, 1) * value_num
        if value_length > 4:
            data_pointer = self._unpack_from("L", pointer + 8)[0]
        else:
            data_pointer = pointer + 8

        format = TYPE_FORMAT.get(value_type, None)

        if format is None:
            # Ascii, Undefined and unknown types
            if value_type == TYPES.Ascii:
                # Crop ending zero
                value_length = max(0, value_length - 1)
            raw_value = self.tiftag[data_pointer:data_pointer+value_length]
            values = (raw_value, )
        else:
            # Unpacked types
            values = self._unpack_from(format * value_num, data_pointer)
            # Collate rationals
            if len(format) > 1:
                stride = len(format)
                values = tuple(
                    values[i*stride:(i+1)*stride] for i in range(value_num)
                )
        return tag, value_type, tuple(values)

    def get_ifd_dict(self, pointer, ifd_name, read_unknown=False):
        ifd_dict = {}
        if pointer > len(self.tiftag) - 2:
            return {}
        tag_count = self._unpack_from("H", pointer)[0]
        ifd_length = 2 + 12 * tag_count
        if pointer > len(self.tiftag) - ifd_length:
            # Truncate IFD
            tag_count = (len(self.tiftag) - 2) // 12
        offset = pointer + 2
        if ifd_name in ["0th", "1st"]:
            t = "Image"
        else:
            t = ifd_name
        for x in range(tag_count):
            pointer = offset + 12 * x
            try:
                tag, value_type, values = self._read_tag(pointer)
            except struct.error:
                # Skip broken tags
                continue
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

        if ifd_name == "0th":
            pointer = offset + 12 * tag_count
            ifd_dict["first_ifd_pointer"] = self.tiftag[pointer:pointer + 4]
        return ifd_dict


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
            return ( b''.join(min(x, 255).to_bytes(1, 'big') for x in value), )
    elif target in SIMPLE_NUMERICS:
        if type in SIMPLE_NUMERICS:
            return value
    raise ValueError('cannot coerce %s to %s' % (type, target))

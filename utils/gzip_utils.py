import StringIO
import gzip
import base64


def get_compressed_base64_from_file(path):
    compressed_stream = StringIO.StringIO()
    with gzip.GzipFile(fileobj=compressed_stream, mode="wb") as compressed, open(path, 'rb') as infile:
        compressed.write(infile.read())
    return base64.b64encode(compressed_stream.getvalue())


def get_compressed_base64_from_binary(bin_bytearray_input):
    compressed_stream = StringIO.StringIO()
    with gzip.GzipFile(fileobj=compressed_stream, mode="wb") as compressed:
        compressed.write(str(bin_bytearray_input))
    return base64.b64encode(compressed_stream.getvalue())

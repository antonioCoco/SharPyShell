import io 
import gzip
import base64


def get_compressed_base64_from_file(path):

    with open(path, 'rb') as f:
        read_data = f.read() 
    return base64.b64encode(gzip.compress(read_data)).decode()


def get_compressed_base64_from_binary(bin_bytearray_input):
    return base64.b64encode(gzip.compress(bin_bytearray_input)).decode()
